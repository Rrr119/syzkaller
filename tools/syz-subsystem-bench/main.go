// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-subsystem-bench compares deterministic description-space coverage for
// subsystem-weighted program generation.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/subsystem/genweight"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS         = flag.String("os", "linux", "target OS")
	flagArch       = flag.String("arch", "amd64", "target architecture")
	flagPrograms   = flag.Int("programs", 1200, "programs generated for every compared mode")
	flagCalls      = flag.Int("calls", 16, "target program length")
	flagSeed       = flag.Int64("seed", 38818, "fixed RNG seed")
	flagWeight     = flag.Float64("weight", 8, "weight multiplier for the selected subsystem")
	flagTmplChance = flag.Int("template-probability", genweight.DefaultTemplateProbability,
		"percentage of programs that start with a subsystem template")
	flagSubsystems = flag.String("subsystems", "bpf,io_uring,kvm", "comma-separated subsystem profiles")
	flagCorpusDir  = flag.String("corpus-dir", "", "optional directory of serialized syzkaller programs")
	flagFormat     = flag.String("format", "markdown", "output format: markdown or json")
	flagOut        = flag.String("out", "", "output file (default stdout)")
)

type ModeResult struct {
	Mode               string  `json:"mode"`
	CallCoverage       float64 `json:"call_coverage"`
	UniqueCalls        int     `json:"unique_calls"`
	PairCoverage       int     `json:"unique_subsystem_pairs"`
	TemplateHits       int     `json:"template_hits"`
	ReproSeed          int64   `json:"repro_seed"`
	ReproProgramSHA256 string  `json:"repro_program_sha256"`
	Reproducible       bool    `json:"reproducible"`
}

type SubsystemResult struct {
	Subsystem       string     `json:"subsystem"`
	AvailableCalls  int        `json:"available_calls"`
	Baseline        ModeResult `json:"baseline"`
	Weighted        ModeResult `json:"weighted"`
	Combined        ModeResult `json:"weighted_and_templates"`
	WeightedGainPP  float64    `json:"weighted_gain_percentage_points"`
	CombinedGainPP  float64    `json:"combined_gain_percentage_points"`
	WeightedRelGain float64    `json:"weighted_relative_gain_pct"`
	CombinedRelGain float64    `json:"combined_relative_gain_pct"`
	CorpusPrograms  int        `json:"corpus_programs"`
}

type Report struct {
	OS         string             `json:"os"`
	Arch       string             `json:"arch"`
	Programs   int                `json:"programs"`
	Calls      int                `json:"calls"`
	Seed       int64              `json:"seed"`
	Weight     float64            `json:"weight"`
	Subsystems []*SubsystemResult `json:"subsystems"`
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		return err
	}
	corpus, err := loadCorpus(target, *flagCorpusDir)
	if err != nil {
		return err
	}
	profileNames := strings.Split(*flagSubsystems, ",")
	var results []*SubsystemResult
	for _, rawName := range profileNames {
		name := genweight.NormalizeName(strings.TrimSpace(rawName))
		if name == "" {
			continue
		}
		profile, ok := findProfile(name)
		if !ok {
			return &genweight.UnknownSubsystemError{Name: rawName}
		}
		available := countAvailableCalls(target, profile.Match)
		baselineCT := target.BuildChoiceTable(corpus, nil)
		weights := map[string]float64{profile.Name: *flagWeight}
		weightedCT := target.BuildChoiceTableWithOptions(corpus, nil, prog.ChoiceTableOptions{
			CallWeight: genweight.CallWeight(weights),
		})
		templates, err := genweight.CompileTemplates(target, profile.Name)
		if err != nil {
			return err
		}
		combinedCT := target.BuildChoiceTableWithOptions(corpus, nil, prog.ChoiceTableOptions{
			CallWeight:          genweight.CallWeight(weights),
			Templates:           templates,
			TemplateProbability: *flagTmplChance,
		})
		baseline := measure(target, profile.Match, nil, baselineCT, "baseline", available)
		weighted := measure(target, profile.Match, nil, weightedCT, "subsystem_weights", available)
		combined := measure(target, profile.Match, templates, combinedCT, "weights_and_templates", available)
		result := &SubsystemResult{
			Subsystem:      profile.Name,
			AvailableCalls: available,
			Baseline:       baseline,
			Weighted:       weighted,
			Combined:       combined,
			CorpusPrograms: len(corpus),
		}
		result.WeightedGainPP = weighted.CallCoverage - baseline.CallCoverage
		result.CombinedGainPP = combined.CallCoverage - baseline.CallCoverage
		result.WeightedRelGain = relativeGain(weighted.CallCoverage, baseline.CallCoverage)
		result.CombinedRelGain = relativeGain(combined.CallCoverage, baseline.CallCoverage)
		results = append(results, result)
	}
	report := &Report{
		OS:         *flagOS,
		Arch:       *flagArch,
		Programs:   *flagPrograms,
		Calls:      *flagCalls,
		Seed:       *flagSeed,
		Weight:     *flagWeight,
		Subsystems: results,
	}
	var out []byte
	if *flagFormat == "json" {
		out, err = json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
	} else {
		out = []byte(renderMarkdown(report))
	}
	if *flagOut == "" {
		fmt.Print(string(out))
		return nil
	}
	return os.WriteFile(*flagOut, out, 0o644)
}

func measure(target *prog.Target, matchers []string, templates []*prog.CompiledCallTemplate,
	ct *prog.ChoiceTable, mode string, available int) ModeResult {
	uniqueCalls := make(map[string]bool)
	uniquePairs := make(map[string]bool)
	templateHits := 0
	var firstProgram string
	var firstHash string
	for i := 0; i < *flagPrograms; i++ {
		seed := *flagSeed + int64(i)*1009
		p := target.Generate(rand.NewSource(seed), *flagCalls, ct)
		if i == 0 {
			firstProgram = string(p.Serialize())
			sum := sha256.Sum256([]byte(firstProgram))
			firstHash = hex.EncodeToString(sum[:])
		}
		ids := make([]int, len(p.Calls))
		for idx, c := range p.Calls {
			ids[idx] = c.Meta.ID
			if matchesAny(c.Meta.Name, matchers) {
				uniqueCalls[c.Meta.Name] = true
			}
		}
		for idx := 1; idx < len(p.Calls); idx++ {
			prev, cur := p.Calls[idx-1].Meta.Name, p.Calls[idx].Meta.Name
			if matchesAny(prev, matchers) && matchesAny(cur, matchers) {
				uniquePairs[prev+" -> "+cur] = true
			}
		}
		if containsTemplateSequence(ids, templates) {
			templateHits++
		}
	}
	repro := target.Generate(rand.NewSource(*flagSeed), *flagCalls, ct)
	reproHashBytes := sha256.Sum256([]byte(repro.Serialize()))
	reproHash := hex.EncodeToString(reproHashBytes[:])
	return ModeResult{
		Mode:               mode,
		CallCoverage:       100 * float64(len(uniqueCalls)) / float64(max(available, 1)),
		UniqueCalls:        len(uniqueCalls),
		PairCoverage:       len(uniquePairs),
		TemplateHits:       templateHits,
		ReproSeed:          *flagSeed,
		ReproProgramSHA256: firstHash,
		Reproducible:       reproHash == firstHash,
	}
}

func containsTemplateSequence(ids []int, templates []*prog.CompiledCallTemplate) bool {
	for _, tmpl := range templates {
		step := 0
		for _, id := range ids {
			if step < len(tmpl.Calls) && id == tmpl.Calls[step].ID {
				step++
			}
		}
		if step == len(tmpl.Calls) {
			return true
		}
	}
	return false
}

func countAvailableCalls(target *prog.Target, matchers []string) int {
	count := 0
	for _, meta := range target.Syscalls {
		if meta.Attrs.Disabled || meta.Attrs.NoGenerate {
			continue
		}
		if matchesAny(meta.Name, matchers) {
			count++
		}
	}
	return count
}

func matchesAny(name string, patterns []string) bool {
	for _, pattern := range patterns {
		if ok, _ := path.Match(pattern, name); ok {
			return true
		}
		if strings.HasSuffix(pattern, "*") &&
			strings.HasPrefix(name, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}
	return false
}

func findProfile(name string) (genweight.Profile, bool) {
	for _, profile := range genweight.Profiles() {
		if genweight.NormalizeName(profile.Name) == name {
			return profile, true
		}
	}
	return genweight.Profile{}, false
}

func relativeGain(value, baseline float64) float64 {
	if baseline == 0 {
		if value == 0 {
			return 0
		}
		return 100
	}
	return 100 * (value - baseline) / baseline
}

func loadCorpus(target *prog.Target, dir string) ([]*prog.Prog, error) {
	if dir == "" {
		return nil, nil
	}
	var corpus []*prog.Prog
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		p, err := target.Deserialize(data, prog.NonStrict)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip corpus file %s: %v\n", path, err)
			return nil
		}
		corpus = append(corpus, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(corpus, func(i, j int) bool {
		return string(corpus[i].Serialize()) < string(corpus[j].Serialize())
	})
	return corpus, nil
}

func renderMarkdown(report *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Subsystem generation benchmark\n\n")
	fmt.Fprintf(&b, "Target: `%s/%s`; programs per mode: %d; target calls: %d; seed: %d; weight: %.1fx.\n\n",
		report.OS, report.Arch, report.Programs, report.Calls, report.Seed, report.Weight)
	b.WriteString("All modes generate program `i` from `seed + 1009*i`. Coverage is deterministic description-space coverage, not kernel PC coverage.\n\n")
	b.WriteString("| Subsystem | Calls baseline | Weighted | Combined | Coverage gain (pp) | Relative gain | Pair baseline → combined | Template hits | Reproducible |\n")
	b.WriteString("|---|---:|---:|---:|---:|---:|---:|---:|:---:|\n")
	for _, r := range report.Subsystems {
		fmt.Fprintf(&b, "| `%s` | %d/%d (%.2f%%) | %d (%.2f%%) | %d (%.2f%%) | %+.2f / %+.2f | %+.1f%% / %+.1f%% | %d → %d | %d/%d | %v |\n",
			r.Subsystem,
			r.Baseline.UniqueCalls, r.AvailableCalls, r.Baseline.CallCoverage,
			r.Weighted.UniqueCalls, r.Weighted.CallCoverage,
			r.Combined.UniqueCalls, r.Combined.CallCoverage,
			r.WeightedGainPP, r.CombinedGainPP,
			r.WeightedRelGain, r.CombinedRelGain,
			r.Baseline.PairCoverage, r.Combined.PairCoverage,
			r.Combined.TemplateHits, report.Programs,
			r.Combined.Reproducible && r.Weighted.Reproducible && r.Baseline.Reproducible)
	}
	b.WriteString("\nReproducibility hashes are SHA-256 of serialized program generated from the base seed in each mode.\n")
	return b.String()
}
