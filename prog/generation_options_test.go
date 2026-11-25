// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyChoiceWeights(t *testing.T) {
	prios := [][]int32{
		{1, 1},
		{0, 0},
	}
	calls := []*Syscall{{ID: 0}, {ID: 1}}
	applyChoiceWeights(prios, calls, func(meta *Syscall) uint64 {
		if meta.ID == 1 {
			return 3
		}
		return 1
	})
	require.Equal(t, int32(5), prios[0][0])
	require.Equal(t, int32(15), prios[0][1])
}

func TestTemplateGenerationIsDeterministic(t *testing.T) {
	target, err := GetTarget("test", "64")
	require.NoError(t, err)
	templates, err := target.CompileCallTemplates([]CallTemplate{{
		Name:      "int-opt",
		Selectors: []string{"test$int", "test$opt0"},
		Weight:    1,
	}})
	require.NoError(t, err)
	ct := target.BuildChoiceTableWithOptions(nil, nil, ChoiceTableOptions{
		Templates:           templates,
		TemplateProbability: 100,
	})

	first := target.Generate(rand.NewSource(38818), 3, ct)
	second := target.Generate(rand.NewSource(38818), 3, ct)
	require.Equal(t, string(first.Serialize()), string(second.Serialize()))
	require.GreaterOrEqual(t, len(first.Calls), 2)
	require.Equal(t, "test$int", first.Calls[0].Meta.Name)
	require.Equal(t, "test$opt0", first.Calls[1].Meta.Name)
}

func TestChoiceTableFiltersTemplateCallsByEnabledSet(t *testing.T) {
	target, err := GetTarget("test", "64")
	require.NoError(t, err)
	templates := target.MustCompileCallTemplates([]CallTemplate{{
		Name:      "int-opt",
		Selectors: []string{"test$int", "test$opt0"},
	}})
	enabled := map[*Syscall]bool{target.SyscallMap["test$int"]: true}
	ct := target.BuildChoiceTableWithOptions(nil, enabled, ChoiceTableOptions{
		Templates:           templates,
		TemplateProbability: 100,
	})
	require.Len(t, ct.templates, 1)
	require.Len(t, ct.templates[0].Calls, 1)
	require.Equal(t, "test$int", ct.templates[0].Calls[0].Name)
}

func TestWeightedChoiceTableAcceptsSerializedCorpus(t *testing.T) {
	target, err := GetTarget("test", "64")
	require.NoError(t, err)
	corpusProgram, err := target.Deserialize([]byte("test$opt0(0x0)"), NonStrict)
	require.NoError(t, err)

	weighted := target.BuildChoiceTableWithOptions([]*Prog{corpusProgram}, nil, ChoiceTableOptions{
		CallWeight: func(meta *Syscall) uint64 { return 2 },
	})
	first := target.Generate(rand.NewSource(38818), 4, weighted)
	second := target.Generate(rand.NewSource(38818), 4, weighted)
	require.Equal(t, string(first.Serialize()), string(second.Serialize()))

	roundTrip, err := target.Deserialize(first.Serialize(), NonStrict)
	require.NoError(t, err)
	require.Equal(t, string(first.Serialize()), string(roundTrip.Serialize()))
}
