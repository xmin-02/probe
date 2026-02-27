// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: Phase 7a — SyzGPT manager-side integration.
// Computes low-frequency syscalls, builds dependency chains, and provides
// corpus examples for AI-guided seed program generation.
package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/aitriage"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

// lfsAlwaysSkipPatterns lists substrings found in syscall names that indicate
// architecture-specific syscalls (e.g. ARM MTE, x32 ABI) which will never
// produce coverage on an x86_64 kernel and waste LFS API budget.
var lfsAlwaysSkipPatterns = []string{
	"TAGGED_ADDR",       // ARM MTE: ARCH_ENABLE_TAGGED_ADDR, ARCH_GET_UNTAG_MASK, etc.
	"FORCE_TAGGED_SVA",  // ARM MTE: ARCH_FORCE_TAGGED_SVA
	"XCOMP_GUEST_PERM",  // ARM AMU: ARCH_REQ_XCOMP_GUEST_PERM
	"XCOMP_PERM",        // ARM AMU: ARCH_REQ_XCOMP_PERM
	"MAP_VDSO_X32",      // x32 ABI vDSO: not active in standard x86_64 kernels
	"GET_MAX_TAG_BITS",  // ARM MTE: ARCH_GET_MAX_TAG_BITS
}

// lfsZeroHits tracks how many consecutive LFS cycles each syscall has been
// selected with zero coverage. After lfsMaxZeroHits it enters cooldown.
var lfsZeroHits = map[string]int{}

// lfsCooldown tracks remaining cooldown cycles per syscall.
var lfsCooldown = map[string]int{}

const lfsMaxZeroHits   = 3 // consecutive zero-cov selections before suppression
const lfsCooldownCycles = 5 // cycles to suppress after hitting the limit

// isLFSBlocked returns true if the syscall should be excluded from LFS targeting.
// It checks the static arch-specific blocklist and the dynamic zero-hit suppressor.
func isLFSBlocked(name string) bool {
	// Static: known non-x86_64 syscalls.
	for _, pat := range lfsAlwaysSkipPatterns {
		if strings.Contains(name, pat) {
			return true
		}
	}
	// Dynamic: cooldown after repeated zero-coverage selections.
	if rem, ok := lfsCooldown[name]; ok && rem > 0 {
		lfsCooldown[name] = rem - 1
		return true
	}
	return false
}

// aiGetLFSTargets identifies low-frequency syscalls and builds LFSTarget structs
// with dependency information and corpus examples for the LLM prompt.
func (mgr *Manager) aiGetLFSTargets(maxTargets int) []aitriage.LFSTarget {
	f := mgr.fuzzer.Load()
	if f == nil {
		return nil
	}

	// Get coverage per syscall from corpus.
	callCov := mgr.corpus.CallCover()

	// Build list of enabled syscalls with low or zero coverage.
	type lfsCandidate struct {
		syscall  *prog.Syscall
		coverage int
	}
	var candidates []lfsCandidate
	for sc := range f.Config.EnabledCalls {
		if sc.Attrs.Disabled || sc.Attrs.NoGenerate {
			continue
		}
		// Skip arch-specific or repeatedly unproductive syscalls.
		if isLFSBlocked(sc.Name) {
			continue
		}
		cov := 0
		if cc := callCov[sc.Name]; cc != nil {
			cov = cc.Count
		}
		// Low frequency: either never covered (0) or rarely covered (<3).
		if cov < 3 {
			candidates = append(candidates, lfsCandidate{syscall: sc, coverage: cov})
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	// Sort: uncovered first, then by name for stability.
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].coverage != candidates[j].coverage {
			return candidates[i].coverage < candidates[j].coverage
		}
		return candidates[i].syscall.Name < candidates[j].syscall.Name
	})

	if len(candidates) > maxTargets {
		candidates = candidates[:maxTargets]
	}

	// Update zero-hit tracker for selected candidates.
	// If a syscall has been selected lfsMaxZeroHits times in a row with cov=0,
	// put it in cooldown so other syscalls get a chance.
	selectedNames := map[string]bool{}
	for _, c := range candidates {
		selectedNames[c.syscall.Name] = true
		if c.coverage == 0 {
			lfsZeroHits[c.syscall.Name]++
			if lfsZeroHits[c.syscall.Name] >= lfsMaxZeroHits {
				lfsCooldown[c.syscall.Name] = lfsCooldownCycles
				delete(lfsZeroHits, c.syscall.Name)
				log.Logf(1, "PROBE: LFS suppressing '%s' for %d cycles (zero-cov %d times)",
					c.syscall.Name, lfsCooldownCycles, lfsMaxZeroHits)
			}
		} else {
			// Coverage appeared — reset the counter.
			delete(lfsZeroHits, c.syscall.Name)
		}
	}

	// Build available syscall name list (for prompt).
	var availableSyscalls []string
	for sc := range f.Config.EnabledCalls {
		if !sc.Attrs.Disabled {
			availableSyscalls = append(availableSyscalls, sc.Name)
		}
	}
	sort.Strings(availableSyscalls)

	// Build LFSTarget for each candidate.
	var targets []aitriage.LFSTarget
	for _, c := range candidates {
		target := mgr.buildLFSTarget(c.syscall, c.coverage, availableSyscalls)
		targets = append(targets, target)
	}

	return targets
}

// buildLFSTarget constructs a detailed LFSTarget with dependency chain and corpus examples.
func (mgr *Manager) buildLFSTarget(sc *prog.Syscall, coverage int, availableSyscalls []string) aitriage.LFSTarget {
	t := aitriage.LFSTarget{
		Name:          sc.Name,
		CallName:      sc.CallName,
		CoverageCount: coverage,
	}

	// Extract argument type descriptions.
	for _, field := range sc.Args {
		t.Args = append(t.Args, describeType(field.Type))
	}

	// Extract return type.
	if sc.Ret != nil {
		t.ReturnType = describeType(sc.Ret)
	}

	// Build input resource dependencies using ForeachCallType.
	resourceSet := make(map[string]bool)
	prog.ForeachCallType(sc, func(typ prog.Type, ctx *prog.TypeCtx) {
		if ctx.Dir == prog.DirOut {
			return // Only care about inputs (DirIn, DirInOut).
		}
		if res, ok := typ.(*prog.ResourceType); ok {
			resName := res.Desc.Name
			if resourceSet[resName] {
				return
			}
			resourceSet[resName] = true

			lfsRes := aitriage.LFSResource{
				ResourceName: resName,
			}

			// Find producers from resource constructors.
			for _, ctor := range res.Desc.Ctors {
				if ctor.Call.ID != sc.ID { // Exclude self.
					lfsRes.Producers = append(lfsRes.Producers, ctor.Call.Name)
				}
			}

			if len(lfsRes.Producers) > 0 {
				t.InputResources = append(t.InputResources, lfsRes)
			}
		}
	})

	// Find corpus examples containing this syscall or related syscalls.
	t.CorpusExamples = mgr.findCorpusExamples(sc, 2)

	return t
}

// describeType returns a human-readable description of a prog.Type.
func describeType(typ prog.Type) string {
	switch t := typ.(type) {
	case *prog.ResourceType:
		return fmt.Sprintf("resource<%s>", t.Desc.Name)
	case *prog.PtrType:
		return fmt.Sprintf("ptr<%s>", describeType(t.Elem))
	case *prog.IntType:
		if t.Kind == prog.IntRange {
			return fmt.Sprintf("int%d[%d:%d]", t.TypeSize*8, t.RangeBegin, t.RangeEnd)
		}
		return fmt.Sprintf("int%d", t.TypeSize*8)
	case *prog.FlagsType:
		return fmt.Sprintf("flags[%s]", t.Name())
	case *prog.ConstType:
		return fmt.Sprintf("const[0x%x]", t.Val)
	case *prog.LenType:
		if len(t.Path) > 0 {
			return fmt.Sprintf("len[%s]", strings.Join(t.Path, "."))
		}
		return "len"
	case *prog.CsumType:
		return "csum"
	case *prog.BufferType:
		switch t.Kind {
		case prog.BufferFilename:
			return "filename"
		case prog.BufferString:
			if t.SubKind != "" {
				return fmt.Sprintf("string[%s]", t.SubKind)
			}
			return "string"
		default:
			return "buffer"
		}
	case *prog.StructType:
		return fmt.Sprintf("struct<%s>", t.Name())
	case *prog.UnionType:
		return fmt.Sprintf("union<%s>", t.Name())
	case *prog.ArrayType:
		return fmt.Sprintf("array<%s>", describeType(t.Elem))
	case *prog.VmaType:
		return "vma"
	case *prog.ProcType:
		return "proc"
	default:
		return typ.Name()
	}
}

// findCorpusExamples searches the corpus for programs containing the target syscall
// or closely related syscalls, returning up to limit serialized examples.
func (mgr *Manager) findCorpusExamples(sc *prog.Syscall, limit int) []string {
	programs := mgr.corpus.Programs()
	if len(programs) == 0 {
		return nil
	}

	type scored struct {
		p     *prog.Prog
		score int
	}
	var matches []scored
	for _, p := range programs {
		score := 0
		for _, c := range p.Calls {
			if c.Meta.ID == sc.ID {
				score += 10 // Exact match.
			} else if c.Meta.CallName == sc.CallName {
				score += 5 // Same base syscall family.
			}
		}
		if score > 0 {
			matches = append(matches, scored{p, score})
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].score > matches[j].score
	})

	var examples []string
	for i := 0; i < limit && i < len(matches); i++ {
		serialized := string(matches[i].p.Serialize())
		// Truncate overly long programs to save LLM tokens.
		if len(serialized) > 1000 {
			serialized = serialized[:1000] + "\n# ... (truncated)"
		}
		examples = append(examples, serialized)
	}
	return examples
}

// extractSyzlangFromLLMResponse strips LLM preamble/postamble text and extracts
// only the syzlang program lines. LLMs often prefix responses with explanatory
// text like "Here's a program that..." which causes Deserialize to fail.
func extractSyzlangFromLLMResponse(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return text
	}

	// Strip markdown code fences.
	if idx := strings.Index(text, "```"); idx >= 0 {
		// Find the content inside the first code fence.
		start := idx + 3
		if nl := strings.IndexByte(text[start:], '\n'); nl >= 0 {
			start += nl + 1
		}
		end := strings.LastIndex(text, "```")
		if end > start {
			text = text[start:end]
		} else {
			text = text[start:]
		}
		text = strings.TrimSpace(text)
	}

	// Filter to syzlang-valid lines: syscall calls, comments, and blank lines.
	// Drop lines that look like natural language (LLM preamble/postamble).
	// Syzlang syscall lines match: ^[a-z_][a-z0-9_$]*(  — lowercase start with '('.
	lines := strings.Split(text, "\n")
	var result []string
	inPreamble := true
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			if !inPreamble {
				result = append(result, line)
			}
			continue
		}
		// Comment lines are valid syzlang.
		if strings.HasPrefix(trimmed, "#") {
			inPreamble = false
			result = append(result, line)
			continue
		}
		// Syzlang syscall lines: start with lowercase letter or underscore, contain '('.
		// This positively matches syscall patterns like "open(", "ioctl$KVM_CREATE(" etc.
		// and rejects English sentences like "Looking at...", "Here is...", "Based on...".
		if len(trimmed) > 0 && (trimmed[0] >= 'a' && trimmed[0] <= 'z' || trimmed[0] == '_') &&
			strings.Contains(trimmed, "(") {
			inPreamble = false
			result = append(result, line)
			continue
		}
		// If we haven't seen any valid lines yet, skip (preamble).
		// If we already have valid lines, stop (postamble).
		if !inPreamble {
			break
		}
	}
	if len(result) == 0 {
		return strings.TrimSpace(text)
	}
	return strings.TrimSpace(strings.Join(result, "\n"))
}

// aiValidateAndInject validates an LLM-generated program and injects it into the fuzzer.
// Returns true if the program was valid and injected.
func (mgr *Manager) aiValidateAndInject(progText string) (bool, error) {
	f := mgr.fuzzer.Load()
	if f == nil {
		return false, fmt.Errorf("fuzzer not ready")
	}

	// Strip LLM preamble/postamble before deserialization.
	progText = extractSyzlangFromLLMResponse(progText)

	// Non-strict deserialization (tolerant of LLM output quirks).
	p, err := mgr.target.Deserialize([]byte(progText), prog.NonStrict)
	if err != nil {
		return false, fmt.Errorf("invalid program: %w", err)
	}

	// Additional sanity checks.
	if len(p.Calls) == 0 {
		return false, fmt.Errorf("empty program")
	}
	if len(p.Calls) > 20 {
		return false, fmt.Errorf("program too long (%d calls)", len(p.Calls))
	}

	// Inject into fuzzer.
	f.InjectProgram(p)
	log.Logf(0, "PROBE: SyzGPT injected program with %d calls", len(p.Calls))
	return true, nil
}
