// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// PROBE: Phase 11g — Generic LRU cache for bounded-memory dedup.
package fuzzer

import (
	"container/list"
	"sync"
)

type lruEntry[K comparable, V any] struct {
	key   K
	value V
}

// LRU is a thread-safe generic LRU cache.
type LRU[K comparable, V any] struct {
	capacity int
	items    map[K]*list.Element
	order    *list.List
	mu       sync.Mutex
}

// NewLRU creates a new LRU cache with the given capacity.
func NewLRU[K comparable, V any](capacity int) *LRU[K, V] {
	return &LRU[K, V]{
		capacity: capacity,
		items:    make(map[K]*list.Element, capacity),
		order:    list.New(),
	}
}

// Get retrieves a value and marks it as recently used.
func (l *LRU[K, V]) Get(key K) (V, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if elem, ok := l.items[key]; ok {
		l.order.MoveToFront(elem)
		return elem.Value.(*lruEntry[K, V]).value, true
	}
	var zero V
	return zero, false
}

// Put inserts or updates a key-value pair.
func (l *LRU[K, V]) Put(key K, value V) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if elem, ok := l.items[key]; ok {
		l.order.MoveToFront(elem)
		elem.Value.(*lruEntry[K, V]).value = value
		return
	}
	entry := &lruEntry[K, V]{key: key, value: value}
	elem := l.order.PushFront(entry)
	l.items[key] = elem
	if l.order.Len() > l.capacity {
		oldest := l.order.Back()
		if oldest != nil {
			l.order.Remove(oldest)
			delete(l.items, oldest.Value.(*lruEntry[K, V]).key)
		}
	}
}

// Len returns the number of items in the cache.
func (l *LRU[K, V]) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.items)
}

// Contains checks if a key exists without updating recency.
func (l *LRU[K, V]) Contains(key K) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.items[key]
	return ok
}
