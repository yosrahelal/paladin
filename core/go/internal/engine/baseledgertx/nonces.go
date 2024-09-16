/*
 * Copyright © 2024 Kaleido, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package baseledgertx

import (
	"context"
	"sync"
	"time"

	"github.com/kaleido-io/paladin/core/internal/engine/enginespi"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
)

type nonceCacheStruct struct {
	nextNonceBySigner map[string]*cachedNonce
	nonceStateTimeout time.Duration
	reaperLock        sync.RWMutex //if this proves to be a bottleneck, we could maintain a finer grained lock on each cache entry but would be more complex and error prone
	inserterLock      sync.Mutex   //we should only ever grab this lock if we have a reader lock on the reaperLock otherwise we could cause a deadlock
	mapMux            sync.Mutex   // only held for a short time during setNextNonceBySigner and getNextNonceBySigner. never attempt to take any other lock while holding this one
	stopChannel       chan struct{}
}

func (nc *nonceCacheStruct) stop() {
	close(nc.stopChannel)
}
func newNonceCache(nonceStateTimeout time.Duration) enginespi.NonceCache {
	n := &nonceCacheStruct{
		nextNonceBySigner: make(map[string]*cachedNonce),
		nonceStateTimeout: nonceStateTimeout,
		stopChannel:       make(chan struct{}),
	}
	go n.reap()
	return n
}

type cachedNonce struct {
	nonceMux    sync.Mutex
	signer      string
	value       uint64
	updatedTime time.Time
}

func (nc *nonceCacheStruct) reap() {
	ticker := time.NewTicker(nc.nonceStateTimeout)
	for {
		select {
		case <-nc.stopChannel:
			ticker.Stop()
			return
		case <-ticker.C:
			nc.reaperLock.Lock()
			defer nc.reaperLock.Unlock()
			now := time.Now()
			for signingAddress, cachedNonce := range nc.nextNonceBySigner {
				if now.Sub(cachedNonce.updatedTime) > nc.nonceStateTimeout {
					delete(nc.nextNonceBySigner, signingAddress)
				}
			}
		}
	}
}

func (nc *nonceCacheStruct) getNextNonceBySigner(signer string) (*cachedNonce, bool) {
	nc.mapMux.Lock()
	defer nc.mapMux.Unlock()
	result, found := nc.nextNonceBySigner[signer]
	return result, found
}

func (nc *nonceCacheStruct) setNextNonceBySigner(signer string, record *cachedNonce) {
	nc.mapMux.Lock()
	defer nc.mapMux.Unlock()
	nc.nextNonceBySigner[signer] = record
}

// Declare an intent to assign a nonce.
// This will ensure that we have a fresh copy of the nonce in memory so that
// the caller can be sure that the nonce assignment step will not suffer the latency of reading the database or calling
// out to the block chain node
// It is the callers responsibility to call `Complete` on the returned object
// The nonce cache for the given signing address is guranteed not to be reaped after IntentToAssignNonce returns and before `complete`
// NOTE:  multiple readers can hold intents to assign concurrently so the nonce is not actually assigned at this point
//
//	nonce assignment itself is protected by a mutex so only one reader can assign at a time but thanks to the pre intent declaration, the assignment is quick
func (nc *nonceCacheStruct) IntentToAssignNonce(ctx context.Context, signer string, nextNonceCB enginespi.NextNonceCallback) (enginespi.NonceAssignmentIntent, error) {

	// take a read lock to block the reaper thread
	nc.reaperLock.RLock()

	cachedNonceRecord, isCached := nc.getNextNonceBySigner(signer)
	if !isCached {
		//we only ever grab the inserterLock if we already have a read lock otherwise there could be a deadlock
		nc.inserterLock.Lock()
		defer nc.inserterLock.Unlock()

		//double check in case another thread managed to get in while we were waiting for the inserterLock
		cachedNonceRecord, isCached = nc.getNextNonceBySigner(signer)

		if !isCached {

			nextNonce, err := nextNonceCB(ctx, signer)
			if err != nil {
				log.L(ctx).Errorf("failed to get next nonce")
				return nil, err
			}

			cachedNonceRecord = &cachedNonce{
				value:       nextNonce,
				signer:      signer,
				updatedTime: time.Now(),
			}

			nc.setNextNonceBySigner(signer, cachedNonceRecord)
		}

	}
	return &nonceAssignmentIntent{
		completed:   false,
		cachedNonce: cachedNonceRecord,
		nonceCache:  nc,
	}, nil
}

type nonceAssignmentIntent struct {
	completed   bool
	cachedNonce *cachedNonce
	nonceCache  *nonceCacheStruct
}

func (i *nonceAssignmentIntent) AssignNextNonce(ctx context.Context) uint64 {
	i.cachedNonce.nonceMux.Lock()
	return i.cachedNonce.value
}

func (i *nonceAssignmentIntent) Complete(ctx context.Context) {
	//increment it for the next reader
	//we still have the nonceMux lock so incrementing is safe
	i.cachedNonce.value = i.cachedNonce.value + 1
	i.cachedNonce.updatedTime = time.Now()
	i.completed = true
	i.cachedNonce.nonceMux.Unlock()
	i.nonceCache.reaperLock.RUnlock()
}

// If Rollback is called after a Complete or another Rollback, it will be a no-op
// thus it is safe to defer Rollback as soon as you have the intent
func (i *nonceAssignmentIntent) Rollback(ctx context.Context) {
	//unlock without incrementing or updating the timestamp
	if !i.completed {
		i.completed = true
		i.cachedNonce.nonceMux.Unlock()
		i.nonceCache.reaperLock.RUnlock()
	}
}
