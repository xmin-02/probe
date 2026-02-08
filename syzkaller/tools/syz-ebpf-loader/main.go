// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: syz-ebpf-loader loads BPF programs for kernel heap monitoring.
// It loads probe_ebpf.bpf.o, attaches to kmem/kfree and kmem/kmalloc tracepoints,
// and pins maps + links to /sys/fs/bpf/probe/ so they persist after this process exits.
//
// Usage:
//   syz-ebpf-loader <path-to-probe_ebpf.bpf.o>
//
// The executor reads the pinned metrics map per-execution via raw bpf() syscall.

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const pinDir = "/sys/fs/bpf/probe"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <probe_ebpf.bpf.o>\n", os.Args[0])
		os.Exit(1)
	}
	bpfObj := os.Args[1]

	if err := run(bpfObj); err != nil {
		fmt.Fprintf(os.Stderr, "PROBE: eBPF loader failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "PROBE: eBPF heap monitor loaded and pinned to %s\n", pinDir)
}

func run(bpfObj string) error {
	// Create pin directory
	if err := os.MkdirAll(pinDir, 0755); err != nil {
		return fmt.Errorf("create pin dir: %w", err)
	}

	// Load BPF object from ELF file
	spec, err := ebpf.LoadCollectionSpec(bpfObj)
	if err != nil {
		return fmt.Errorf("load collection spec: %w", err)
	}

	// Load into kernel
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create collection: %w", err)
	}
	defer coll.Close()

	// Pin maps so executor can access them
	metricsMap := coll.Maps["metrics"]
	if metricsMap == nil {
		return fmt.Errorf("metrics map not found in BPF object")
	}
	metricsPin := filepath.Join(pinDir, "metrics")
	// Remove stale pin if exists
	os.Remove(metricsPin)
	if err := metricsMap.Pin(metricsPin); err != nil {
		return fmt.Errorf("pin metrics map: %w", err)
	}

	freedMap := coll.Maps["freed_objects"]
	if freedMap == nil {
		return fmt.Errorf("freed_objects map not found in BPF object")
	}
	freedPin := filepath.Join(pinDir, "freed_objects")
	os.Remove(freedPin)
	if err := freedMap.Pin(freedPin); err != nil {
		return fmt.Errorf("pin freed_objects map: %w", err)
	}

	// Attach to tracepoints
	kfreeProg := coll.Programs["trace_kfree"]
	if kfreeProg == nil {
		return fmt.Errorf("trace_kfree program not found")
	}
	kfreeLink, err := link.Tracepoint("kmem", "kfree", kfreeProg, nil)
	if err != nil {
		return fmt.Errorf("attach kfree tracepoint: %w", err)
	}

	kmallocProg := coll.Programs["trace_kmalloc"]
	if kmallocProg == nil {
		return fmt.Errorf("trace_kmalloc program not found")
	}
	kmallocLink, err := link.Tracepoint("kmem", "kmalloc", kmallocProg, nil)
	if err != nil {
		kfreeLink.Close()
		return fmt.Errorf("attach kmalloc tracepoint: %w", err)
	}

	// Pin links so BPF programs persist after loader exits
	kfreeLinkPin := filepath.Join(pinDir, "link_kfree")
	os.Remove(kfreeLinkPin)
	if err := kfreeLink.Pin(kfreeLinkPin); err != nil {
		return fmt.Errorf("pin kfree link: %w", err)
	}

	kmallocLinkPin := filepath.Join(pinDir, "link_kmalloc")
	os.Remove(kmallocLinkPin)
	if err := kmallocLink.Pin(kmallocLinkPin); err != nil {
		return fmt.Errorf("pin kmalloc link: %w", err)
	}

	// Success — BPF programs are attached and pinned, loader can exit
	return nil
}
