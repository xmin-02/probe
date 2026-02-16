// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"sync"
	"sync/atomic"

	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
)

// Cover keeps track of the signal known to the fuzzer.
type Cover struct {
	mu               sync.RWMutex
	maxSignal        signal.Signal // max signal ever observed (including flakes)
	newSignal        signal.Signal // newly identified max signal
	maxSignalLenCache atomic.Int64 // PROBE: lock-free cache of len(maxSignal)
}

func newCover() *Cover {
	cover := new(Cover)
	stat.New("max signal", "Maximum fuzzing signal (including flakes)",
		stat.Graph("signal"), stat.LenOf(&cover.maxSignal, &cover.mu))
	return cover
}

func (cover *Cover) addRawMaxSignal(signal []uint64, prio uint8) signal.Signal {
	cover.mu.Lock()
	diff := cover.maxSignal.DiffRaw(signal, prio)
	if diff.Empty() {
		cover.mu.Unlock()
		return diff
	}
	cover.maxSignal.Merge(diff)
	cover.newSignal.Merge(diff)
	cover.maxSignalLenCache.Store(int64(cover.maxSignal.Len()))
	cover.mu.Unlock()
	return diff
}

func (cover *Cover) CopyMaxSignal() signal.Signal {
	cover.mu.RLock()
	defer cover.mu.RUnlock()
	return cover.maxSignal.Copy()
}

// PROBE: MaxSignalLen returns the current size of the max signal set.
// Uses lock-free atomic cache updated by addRawMaxSignal.
func (cover *Cover) MaxSignalLen() int {
	return int(cover.maxSignalLenCache.Load())
}

func (cover *Cover) GrabSignalDelta() signal.Signal {
	cover.mu.Lock()
	defer cover.mu.Unlock()
	plus := cover.newSignal
	cover.newSignal = nil
	return plus
}
