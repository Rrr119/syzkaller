// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package genweight maps kernel subsystems to syscall descriptions and builds
// deterministic generation weights and call templates.
package genweight

import (
	"math"
	"path"
	"strings"

	"github.com/google/syzkaller/pkg/subsystem"
	_ "github.com/google/syzkaller/pkg/subsystem/lists" // Register the Linux MAINTAINERS-derived list.
	"github.com/google/syzkaller/prog"
)

// DefaultTemplateProbability is the default percentage of generated programs
// that start with a subsystem call template when subsystem weighting is on.
const DefaultTemplateProbability = 35

// Profile describes one subsystem's call matchers and structural templates.
type Profile struct {
	Name      string
	Match     []string
	Templates []prog.CallTemplate
}

// Profiles returns the built-in subsystem profiles used by the benchmark and
// manager integration.
func Profiles() []Profile {
	return []Profile{
		{
			Name: "bpf",
			Match: []string{
				"bpf",
				"bpf$*",
				"syz_bpf*",
			},
			Templates: []prog.CallTemplate{
				{
					Name:   "bpf-map-lifecycle",
					Weight: 2,
					Selectors: []string{
						"bpf$MAP_CREATE",
						"bpf$MAP_UPDATE_ELEM",
						"bpf$MAP_LOOKUP_ELEM",
					},
				},
				{
					Name:   "bpf-program-attach-run",
					Weight: 1,
					Selectors: []string{
						"bpf$PROG_LOAD",
						"bpf$BPF_PROG_ATTACH",
						"bpf$BPF_PROG_TEST_RUN",
					},
				},
			},
		},
		{
			Name: "io-uring",
			Match: []string{
				"io_uring*",
				"syz_io_uring_*",
			},
			Templates: []prog.CallTemplate{
				{
					Name:   "io-uring-setup-submit-complete",
					Weight: 1,
					Selectors: []string{
						"syz_io_uring_setup",
						"syz_io_uring_submit",
						"io_uring_enter",
						"syz_io_uring_complete",
					},
				},
				{
					Name:   "io-uring-register-enter",
					Weight: 1,
					Selectors: []string{
						"io_uring_setup",
						"io_uring_register$*",
						"io_uring_enter",
					},
				},
			},
		},
		{
			Name: "kvm",
			Match: []string{
				"openat$kvm",
				"ioctl$KVM_*",
				"syz_kvm_*",
			},
			Templates: []prog.CallTemplate{
				{
					Name:   "kvm-device-vm-vcpu-run",
					Weight: 2,
					Selectors: []string{
						"openat$kvm",
						"ioctl$KVM_CREATE_VM",
						"syz_kvm_setup_syzos_vm$*",
						"syz_kvm_add_vcpu$*",
						"ioctl$KVM_RUN",
					},
				},
				{
					Name:   "kvm-vm-configure",
					Weight: 1,
					Selectors: []string{
						"openat$kvm",
						"ioctl$KVM_CREATE_VM",
						"ioctl$KVM_SET_USER_MEMORY_REGION",
						"ioctl$KVM_CREATE_IRQCHIP",
					},
				},
			},
		},
	}
}

func profileMap() map[string]Profile {
	ret := make(map[string]Profile)
	for _, profile := range Profiles() {
		ret[NormalizeName(profile.Name)] = profile
	}
	return ret
}

// NormalizeName accepts both io_uring and io-uring spelling.
func NormalizeName(name string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), "_", "-")
}

var explicitLinuxSyscalls = func() map[string][]string {
	ret := make(map[string][]string)
	for _, ss := range subsystem.GetList("linux") {
		name := NormalizeName(ss.Name)
		for _, call := range ss.Syscalls {
			ret[call] = append(ret[call], name)
		}
	}
	return ret
}()

// CallSubsystems returns normalized subsystem names associated with a call.
func CallSubsystems(meta *prog.Syscall) []string {
	if meta == nil {
		return nil
	}
	seen := make(map[string]bool)
	var ret []string
	add := func(name string) {
		name = NormalizeName(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		ret = append(ret, name)
	}
	if meta.Attrs.Subsystem != "" {
		for _, name := range strings.Split(meta.Attrs.Subsystem, ",") {
			add(name)
		}
	}
	for _, name := range explicitLinuxSyscalls[meta.Name] {
		add(name)
	}
	for _, profile := range Profiles() {
		if matchesAny(meta.Name, profile.Match) {
			add(profile.Name)
		}
	}
	return ret
}

func matchesAny(name string, patterns []string) bool {
	for _, pattern := range patterns {
		if ok, err := path.Match(pattern, name); err == nil && ok {
			return true
		}
		if strings.HasSuffix(pattern, "*") &&
			strings.HasPrefix(name, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}
	return false
}

// CallWeight builds a ChoiceTableOptions weight callback. Weight values are
// relative multipliers: 1.0 is the default, 8.0 strongly favors a subsystem,
// and values below 1.0 de-emphasize it.
func CallWeight(weights map[string]float64) func(*prog.Syscall) uint64 {
	if len(weights) == 0 {
		return nil
	}
	normalized := make(map[string]float64, len(weights))
	for name, weight := range weights {
		normalized[NormalizeName(name)] = weight
	}
	return func(meta *prog.Syscall) uint64 {
		weight := 1.0
		for _, name := range CallSubsystems(meta) {
			if w := normalized[name]; !math.IsNaN(w) {
				weight = math.Max(weight, w)
			}
		}
		if weight <= 0 || math.IsNaN(weight) || math.IsInf(weight, 0) {
			return 1
		}
		return uint64(math.Round(weight * 1000))
	}
}

// BuildOptions creates the generation options used by syz-manager. Templates
// are only attached for built-in profiles explicitly present in weights.
func BuildOptions(target *prog.Target, weights map[string]float64,
	probability *int) (prog.ChoiceTableOptions, error) {
	opts := prog.ChoiceTableOptions{}
	if len(weights) == 0 {
		return opts, nil
	}
	opts.CallWeight = CallWeight(weights)
	opts.TemplateProbability = DefaultTemplateProbability
	if probability != nil {
		opts.TemplateProbability = *probability
	}
	if opts.TemplateProbability == 0 {
		return opts, nil
	}
	normalized := make(map[string]bool, len(weights))
	for name := range weights {
		normalized[NormalizeName(name)] = true
	}
	for _, profile := range Profiles() {
		if !normalized[NormalizeName(profile.Name)] {
			continue
		}
		templates, err := CompileTemplates(target, profile.Name)
		if err != nil {
			return prog.ChoiceTableOptions{}, err
		}
		opts.Templates = append(opts.Templates, templates...)
	}
	return opts, nil
}

// CompileTemplates compiles templates for the named profiles. An empty names
// list compiles all built-in templates. Unknown names or selectors absent from
// the target result in an error.
func CompileTemplates(target *prog.Target, names ...string) ([]*prog.CompiledCallTemplate, error) {
	profiles := profileMap()
	var raw []prog.CallTemplate
	if len(names) == 0 {
		for _, profile := range Profiles() {
			raw = append(raw, profile.Templates...)
		}
	} else {
		for _, name := range names {
			profile, ok := profiles[NormalizeName(name)]
			if !ok {
				return nil, &UnknownSubsystemError{Name: name}
			}
			raw = append(raw, profile.Templates...)
		}
	}
	return target.CompileCallTemplates(raw)
}

// UnknownSubsystemError indicates that no built-in profile exists for a name.
type UnknownSubsystemError struct {
	Name string
}

func (err *UnknownSubsystemError) Error() string {
	return "unknown generation subsystem profile: " + err.Name
}
