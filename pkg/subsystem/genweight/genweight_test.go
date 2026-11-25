// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package genweight_test

import (
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/subsystem/genweight"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/stretchr/testify/require"
)

func TestCallSubsystems(t *testing.T) {
	target, err := prog.GetTarget("linux", "amd64")
	require.NoError(t, err)
	tests := map[string]string{
		"bpf$MAP_CREATE":             "bpf",
		"syz_io_uring_setup":         "io-uring",
		"io_uring_enter":             "io-uring",
		"openat$kvm":                 "kvm",
		"ioctl$KVM_CREATE_VM":        "kvm",
		"syz_kvm_setup_syzos_vm$x86": "kvm",
	}
	for callName, want := range tests {
		meta := target.SyscallMap[callName]
		require.NotNil(t, meta, callName)
		require.Contains(t, genweight.CallSubsystems(meta), want, callName)
	}
	require.Equal(t, "bpf", target.SyscallMap["bpf$MAP_CREATE"].Attrs.Subsystem)
	require.Equal(t, "io_uring", target.SyscallMap["io_uring_enter"].Attrs.Subsystem)
	require.Equal(t, "kvm", target.SyscallMap["openat$kvm"].Attrs.Subsystem)
}

func TestCompileBuiltinTemplates(t *testing.T) {
	target, err := prog.GetTarget("linux", "amd64")
	require.NoError(t, err)
	for _, name := range []string{"bpf", "io_uring", "kvm"} {
		templates, err := genweight.CompileTemplates(target, name)
		require.NoError(t, err)
		require.NotEmpty(t, templates)
		for _, tmpl := range templates {
			require.NotEmpty(t, tmpl.Calls)
		}
	}
}

func TestCallWeightNormalizesSpellings(t *testing.T) {
	target, err := prog.GetTarget("linux", "amd64")
	require.NoError(t, err)
	weight := genweight.CallWeight(map[string]float64{"io_uring": 4})(target.SyscallMap["io_uring_enter"])
	require.Equal(t, uint64(4000), weight)
}

func TestThreeSubsystemsCoverageLiftAndDeterminism(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping quantitative generation test in short mode")
	}
	target, err := prog.GetTarget("linux", "amd64")
	require.NoError(t, err)
	for _, name := range []string{"bpf", "io_uring", "kvm"} {
		t.Run(name, func(t *testing.T) {
			templates, err := genweight.CompileTemplates(target, name)
			require.NoError(t, err)
			weights := map[string]float64{name: 8}
			baselineCT := target.BuildChoiceTable(nil, nil)
			weightedCT := target.BuildChoiceTableWithOptions(nil, nil, prog.ChoiceTableOptions{
				CallWeight: genweight.CallWeight(weights),
			})
			combinedCT := target.BuildChoiceTableWithOptions(nil, nil, prog.ChoiceTableOptions{
				CallWeight:          genweight.CallWeight(weights),
				Templates:           templates,
				TemplateProbability: genweight.DefaultTemplateProbability,
			})

			baseline := generatedCallSet(target, baselineCT, name, 38818)
			weighted := generatedCallSet(target, weightedCT, name, 38818)
			combined := generatedCallSet(target, combinedCT, name, 38818)
			require.Greater(t, len(weighted), len(baseline)+15)
			require.Greater(t, len(combined), len(baseline)+20)

			first := target.Generate(rand.NewSource(38818), 16, combinedCT)
			second := target.Generate(rand.NewSource(38818), 16, combinedCT)
			require.Equal(t, string(first.Serialize()), string(second.Serialize()))
		})
	}
}

func generatedCallSet(target *prog.Target, ct *prog.ChoiceTable, subsystem string,
	seed int64) map[string]bool {
	calls := make(map[string]bool)
	for i := 0; i < 160; i++ {
		p := target.Generate(rand.NewSource(seed+int64(i)*1009), 16, ct)
		for _, c := range p.Calls {
			for _, got := range genweight.CallSubsystems(c.Meta) {
				if got == genweight.NormalizeName(subsystem) {
					calls[c.Meta.Name] = true
				}
			}
		}
	}
	return calls
}
