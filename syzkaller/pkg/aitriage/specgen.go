// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: Phase 10 — AI-guided syzlang spec generation engine (stepD).
// Analyzes coverage gaps, generates syzlang spec drafts via LLM,
// and saves to workdir/specgen/ for the dashboard and manual validation.
package aitriage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
)

// SpecGap represents an uncovered or low-coverage syscall family.
type SpecGap struct {
	Driver        string
	SyscallFamily string
	Coverage      int
	Syscalls      []string
	ZeroCovCount  int
}

// InitSpecGen initializes the spec generation engine with its own LLM client.
func (t *Triager) InitSpecGen(cfg mgrconfig.AISpecGenConfig) error {
	if cfg.APIKey == "" {
		return nil
	}
	triageCfg := mgrconfig.AITriageConfig{
		Provider: cfg.Provider,
		Model:    cfg.Model,
		APIKey:   cfg.APIKey,
		APIURL:   cfg.APIURL,
	}
	if triageCfg.Provider == "" {
		triageCfg.Provider = "openai" // DeepSeek uses OpenAI-compatible API
	}
	client, err := NewClient(triageCfg)
	if err != nil {
		return fmt.Errorf("specgen client: %w", err)
	}
	t.specGenClient = client
	t.specGenModel = cfg.Model
	t.logf("[SpecGen] Initialized: model=%s provider=%s", cfg.Model, triageCfg.Provider)
	return nil
}

// stepD runs AI-guided syzlang spec generation for uncovered drivers.
// Runs at most once every 6 hours to avoid excessive LLM calls.
func (t *Triager) stepD(ctx context.Context) {
	if t.specGenClient == nil {
		return
	}
	if t.GetSnapshot == nil {
		return
	}

	snap := t.GetSnapshot()
	if snap == nil {
		t.logf("[Step D] No snapshot available, skipping spec generation")
		return
	}

	// Rate limit: only run every 6 hours.
	t.mu.Lock()
	if !t.lastSpecGen.IsZero() && time.Since(t.lastSpecGen) < 6*time.Hour {
		t.mu.Unlock()
		return
	}
	t.lastSpecGen = time.Now()
	t.mu.Unlock()

	gaps := analyzeSpecGaps(snap)
	if len(gaps) == 0 {
		t.logf("[Step D] No uncovered drivers found for spec generation")
		return
	}

	// Phase 14 W5a-14b: Trigger Focus for identified gaps (auto-concentrate).
	// This provides immediate feedback on gap syscalls while specs are being generated.
	if t.TriggerFocusForGap != nil {
		focusTriggered := 0
		for _, gap := range gaps {
			count := t.TriggerFocusForGap(gap.SyscallFamily, gap.Syscalls)
			if count > 0 {
				focusTriggered += count
				t.logf("[Step D] Focus auto-concentrate: triggered %d programs for '%s' gap",
					count, gap.SyscallFamily)
			}
		}
		if focusTriggered > 0 {
			t.logf("[Step D] Focus auto-concentrate: %d total programs triggered across %d gaps",
				focusTriggered, len(gaps))
		}
	}

	// Skip already-generated drivers.
	gaps = t.filterExistingSpecs(gaps)
	if len(gaps) == 0 {
		t.logf("[Step D] All gap drivers already have spec drafts")
		return
	}

	// Generate specs for top 3 gaps per batch.
	maxPerBatch := 3
	if len(gaps) > maxPerBatch {
		gaps = gaps[:maxPerBatch]
	}

	t.logf("[Step D] SpecGen starting: %d gaps, generating %d specs", len(gaps), len(gaps))

	generated, succeeded := 0, 0
	for i, gap := range gaps {
		select {
		case <-ctx.Done():
			return
		default:
		}

		t.logf("[Step D] [%d/%d] Generating spec for '%s' (cov=%d, zero=%d/%d)",
			i+1, len(gaps), gap.Driver, gap.Coverage, gap.ZeroCovCount, len(gap.Syscalls))

		spec, err := t.generateSpecDraft(ctx, gap)
		if err != nil {
			t.logf("[Step D] [%d/%d] Failed for '%s': %v", i+1, len(gaps), gap.Driver, err)
			t.saveSpecStatus(gap.Driver, "failed", "", 0, err.Error())
			continue
		}
		generated++

		if err := t.saveSpecDraft(gap.Driver, spec); err != nil {
			t.logf("[Step D] [%d/%d] Save failed for '%s': %v", i+1, len(gaps), gap.Driver, err)
			continue
		}
		succeeded++
		t.logf("[Step D] [%d/%d] Draft saved for '%s' (%d syscalls)",
			i+1, len(gaps), gap.Driver, countSyscalls(spec))

		time.Sleep(3 * time.Second) // Rate limit between API calls.
	}

	t.logf("[Step D] SpecGen batch complete: %d generated, %d saved (of %d gaps)",
		generated, succeeded, len(gaps))

	// D13: Log per-type cost breakdown.
	t.cost.mu.Lock()
	stepDCost := t.cost.StepDCostUSD
	stepDCalls := t.cost.StepDCalls
	t.cost.mu.Unlock()
	t.logf("[Step D] SpecGen cost: $%.4f (%d calls)", stepDCost, stepDCalls)

	// Phase 14 W5a-14a: Auto-inject generated specs as seed programs.
	if succeeded > 0 {
		t.injectSpecSeeds(ctx)
	}
}

// analyzeSpecGaps identifies syscall families with zero or very low coverage.
// Note: SyscallCoverage only includes syscalls present in the corpus (from CallCover).
// Syscalls with truly zero corpus entries won't appear in the map at all.
// We use relaxed thresholds to catch families with even partial low coverage.
func analyzeSpecGaps(snap *FuzzingSnapshot) []SpecGap {
	if snap.SyscallCoverage == nil || len(snap.SyscallCoverage) == 0 {
		log.Logf(1, "PROBE: [SpecGen] analyzeSpecGaps: SyscallCoverage is empty (corpus may be empty or CallCover not populated)")
		return nil
	}

	log.Logf(1, "PROBE: [SpecGen] analyzeSpecGaps: %d syscalls in coverage map", len(snap.SyscallCoverage))

	// Group syscalls by family (prefix before '$').
	type familyInfo struct {
		syscalls []string
		totalCov int
		zeroCov  int
	}
	families := make(map[string]*familyInfo)
	for name, cov := range snap.SyscallCoverage {
		family := name
		if idx := strings.IndexByte(name, '$'); idx >= 0 {
			family = name[:idx]
		}
		fi := families[family]
		if fi == nil {
			fi = &familyInfo{}
			families[family] = fi
		}
		fi.syscalls = append(fi.syscalls, name)
		fi.totalCov += cov
		if cov == 0 {
			fi.zeroCov++
		}
	}

	log.Logf(1, "PROBE: [SpecGen] analyzeSpecGaps: %d families found", len(families))

	// Find families with low coverage.
	// Relaxed criteria: include single-syscall families with zero coverage,
	// and families where >=30% of syscalls have zero coverage.
	var gaps []SpecGap
	for family, fi := range families {
		// Single-syscall families: only include if zero coverage.
		if len(fi.syscalls) == 1 {
			if fi.totalCov == 0 {
				gaps = append(gaps, SpecGap{
					Driver:        family,
					SyscallFamily: family,
					Coverage:      fi.totalCov,
					Syscalls:      fi.syscalls,
					ZeroCovCount:  fi.zeroCov,
				})
			}
			continue
		}
		// Multi-syscall families: >=30% zero coverage ratio.
		zeroRatio := float64(fi.zeroCov) / float64(len(fi.syscalls))
		if zeroRatio < 0.3 {
			continue
		}
		gaps = append(gaps, SpecGap{
			Driver:        family,
			SyscallFamily: family,
			Coverage:      fi.totalCov,
			Syscalls:      fi.syscalls,
			ZeroCovCount:  fi.zeroCov,
		})
	}

	log.Logf(1, "PROBE: [SpecGen] analyzeSpecGaps: %d gaps identified", len(gaps))

	// Sort by coverage (lowest first), then by zero-coverage count (highest first).
	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].Coverage != gaps[j].Coverage {
			return gaps[i].Coverage < gaps[j].Coverage
		}
		return gaps[i].ZeroCovCount > gaps[j].ZeroCovCount
	})

	return gaps
}

// filterExistingSpecs removes gaps that already have non-failed spec drafts.
func (t *Triager) filterExistingSpecs(gaps []SpecGap) []SpecGap {
	specDir := filepath.Join(t.workdir, "specgen")
	var filtered []SpecGap
	for _, g := range gaps {
		statusFile := filepath.Join(specDir, g.Driver, "status.json")
		if data, err := os.ReadFile(statusFile); err == nil {
			var st struct {
				Status string `json:"status"`
			}
			if json.Unmarshal(data, &st) == nil && st.Status != "failed" {
				continue // Already has a non-failed spec.
			}
		}
		filtered = append(filtered, g)
	}
	return filtered
}

const specGenSystemPrompt = `You are a Linux kernel syzlang specification expert for syzkaller fuzzer.
Generate syzkaller syscall descriptions (syzlang format) for the given kernel subsystem.

Rules:
1. Use correct syzlang syntax: resource, type, flags, define, include directives
2. Argument types: int8/16/32/64, ptr[in/out/inout], array, string, flags, const, len, bytesize
3. Define resource types for file descriptors and kernel handles
4. Include ioctl commands with proper cmd constants and struct arg types
5. Use include directives for relevant kernel headers (e.g., include <uapi/linux/...>)
6. Define flags and constants with realistic kernel values
7. Keep specifications focused and syntactically correct
8. Use the syz_ prefix for pseudo-syscalls only when needed

Output ONLY the syzlang specification, no markdown fences or explanations.`

func (t *Triager) generateSpecDraft(ctx context.Context, gap SpecGap) (string, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Generate a syzlang specification for the Linux kernel '%s' subsystem.\n\n", gap.Driver)
	fmt.Fprintf(&sb, "Known syscalls in this family (%d total, %d with zero coverage):\n",
		len(gap.Syscalls), gap.ZeroCovCount)
	// Limit listed syscalls to avoid token explosion.
	listed := gap.Syscalls
	if len(listed) > 30 {
		listed = listed[:30]
	}
	for _, sc := range listed {
		fmt.Fprintf(&sb, "  - %s\n", sc)
	}
	if len(gap.Syscalls) > 30 {
		fmt.Fprintf(&sb, "  ... and %d more\n", len(gap.Syscalls)-30)
	}
	fmt.Fprintf(&sb, "\nGenerate syzlang descriptions that would help the fuzzer reach these syscalls.\n")
	fmt.Fprintf(&sb, "Focus on: resource definitions, ioctl commands, struct types, and flag constants.\n")

	resp, err := t.specGenClient.Chat(ctx, specGenSystemPrompt, sb.String())
	if err != nil {
		return "", fmt.Errorf("LLM call: %w", err)
	}

	// Track cost.
	call := APICall{
		Time:         time.Now(),
		Type:         "specgen",
		InputTokens:  resp.InputTokens,
		OutputTokens: resp.OutputTokens,
	}
	t.cost.Record(call, t.specGenModel)
	saveCostTracker(t.workdir, t.cost)

	// Also write specgen-specific cost for the dashboard.
	t.saveSpecGenCost(call)

	// Strip markdown code blocks if present.
	spec := resp.Content
	spec = strings.TrimPrefix(spec, "```syzlang\n")
	spec = strings.TrimPrefix(spec, "```\n")
	if idx := strings.LastIndex(spec, "```"); idx >= 0 {
		spec = spec[:idx]
	}
	spec = strings.TrimSpace(spec)

	if len(spec) < 20 {
		return "", fmt.Errorf("spec too short (%d chars)", len(spec))
	}

	return spec, nil
}

func (t *Triager) saveSpecDraft(driver, spec string) error {
	specDir := filepath.Join(t.workdir, "specgen", driver)
	if err := os.MkdirAll(specDir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	specFile := filepath.Join(specDir, driver+".txt")
	if err := os.WriteFile(specFile, []byte(spec), 0644); err != nil {
		return fmt.Errorf("write spec: %w", err)
	}

	t.saveSpecStatus(driver, "pending", specFile, countSyscalls(spec), "")
	return nil
}

func (t *Triager) saveSpecStatus(driver, status, path string, syscalls int, errMsg string) {
	specDir := filepath.Join(t.workdir, "specgen", driver)
	os.MkdirAll(specDir, 0755)

	st := struct {
		Status   string `json:"status"`
		Path     string `json:"path"`
		Coverage int    `json:"coverage"`
		Syscalls int    `json:"syscalls"`
		Created  string `json:"created"`
		Error    string `json:"error,omitempty"`
	}{
		Status:   status,
		Path:     path,
		Syscalls: syscalls,
		Created:  time.Now().Format("2006-01-02 15:04"),
		Error:    errMsg,
	}
	data, _ := json.MarshalIndent(st, "", "  ")
	os.WriteFile(filepath.Join(specDir, "status.json"), data, 0644)
}

// saveSpecGenCost appends a cost entry to workdir/specgen_cost.json for the dashboard.
func (t *Triager) saveSpecGenCost(call APICall) {
	costFile := filepath.Join(t.workdir, "specgen_cost.json")

	var cost struct {
		TotalCalls        int       `json:"total_calls"`
		TotalInputTokens  int       `json:"total_input_tokens"`
		TotalOutputTokens int       `json:"total_output_tokens"`
		TotalCostUSD      float64   `json:"total_cost_usd"`
		Calls             []APICall `json:"calls"`
	}

	if data, err := os.ReadFile(costFile); err == nil {
		json.Unmarshal(data, &cost)
	}

	cost.TotalCalls++
	cost.TotalInputTokens += call.InputTokens
	cost.TotalOutputTokens += call.OutputTokens
	cost.TotalCostUSD += call.CostUSD
	cost.Calls = append(cost.Calls, call)

	if len(cost.Calls) > 200 {
		cost.Calls = cost.Calls[len(cost.Calls)-200:]
	}

	data, _ := json.MarshalIndent(cost, "", "  ")
	os.WriteFile(costFile, data, 0644)
}

// countSyscalls counts syscall definitions in a syzlang spec.
func countSyscalls(spec string) int {
	count := 0
	for _, line := range strings.Split(spec, "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if strings.Contains(line, "(") &&
			!strings.HasPrefix(line, "include") &&
			!strings.HasPrefix(line, "resource") &&
			!strings.HasPrefix(line, "type") &&
			!strings.HasPrefix(line, "define") {
			count++
		}
	}
	return count
}

// Phase 14 W5a-14a: injectSpecSeeds reads generated spec files and injects them as seed programs.
// Quality gate: seeds with no coverage gain after 3 attempts are discarded.
func (t *Triager) injectSpecSeeds(ctx context.Context) {
	if t.ValidateAndInjectProg == nil {
		t.logf("[SpecGen→Seed] ValidateAndInjectProg callback not set, skipping injection")
		return
	}

	specDir := filepath.Join(t.workdir, "specgen")
	entries, err := os.ReadDir(specDir)
	if err != nil {
		t.logf("[SpecGen→Seed] Failed to read specgen dir: %v", err)
		return
	}

	injected, failed := 0, 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		driver := entry.Name()
		specFile := filepath.Join(specDir, driver, driver+".txt")

		// Check if spec file exists
		data, err := os.ReadFile(specFile)
		if err != nil {
			continue
		}

		specText := string(data)
		if len(specText) == 0 {
			continue
		}

		// Check status - only inject "pending" specs (not already tested)
		statusFile := filepath.Join(specDir, driver, "status.json")
		var status struct {
			Status string `json:"status"`
		}
		if statusData, err := os.ReadFile(statusFile); err == nil {
			json.Unmarshal(statusData, &status)
			if status.Status != "pending" {
				continue // Skip if already processed
			}
		}

		// Attempt injection with quality gate (3 attempts max)
		success := false
		for attempt := 1; attempt <= 3; attempt++ {
			ok, err := t.ValidateAndInjectProg(specText)
			if err != nil {
				t.logf("[SpecGen→Seed] Driver '%s' attempt %d/%d failed: %v", driver, attempt, 3, err)
				continue
			}
			if ok {
				success = true
				injected++
				t.logf("[SpecGen→Seed] Driver '%s' injected successfully", driver)
				// Update status to "injected"
				t.saveSpecStatus(driver, "injected", specFile, countSyscalls(specText), "")
				break
			}
		}

		if !success {
			failed++
			t.logf("[SpecGen→Seed] Driver '%s' failed after 3 attempts (no coverage gain)", driver)
			// Update status to "no_coverage"
			t.saveSpecStatus(driver, "no_coverage", specFile, countSyscalls(specText), "no coverage gain after 3 attempts")
		}
	}

	if injected > 0 || failed > 0 {
		t.logf("[SpecGen→Seed] Complete: %d injected, %d failed (no coverage)", injected, failed)
	}
}
