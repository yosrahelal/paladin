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

package publictxmgr

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type NextNonceCallback func(ctx context.Context, signer tktypes.EthAddress) (uint64, error)

type NonceAssignmentIntent interface {
	Complete(ctx context.Context)
	AssignNextNonce(ctx context.Context) (uint64, error)
	Address() tktypes.EthAddress
	Rollback(ctx context.Context)
}

type NonceCache interface {
	IntentToAssignNonce(ctx context.Context, signer tktypes.EthAddress) (NonceAssignmentIntent, error)
	Stop()
}

type nonceCacheStruct struct {
	nextNonceBySigner map[tktypes.EthAddress]*cachedNonce
	nextNonceCB       NextNonceCallback
	nonceStateTimeout time.Duration
	reaperLock        sync.RWMutex //if this proves to be a bottleneck, we could maintain a finer grained lock on each cache entry but would be more complex and error prone
	inserterLock      sync.Mutex   //we should only ever grab this lock if we have a reader lock on the reaperLock otherwise we could cause a deadlock
	mapMux            sync.Mutex   // only held for a short time during setNextNonceBySigner and getNextNonceBySigner. never attempt to take any other lock while holding this one
	stopChannel       chan struct{}
}

func (nc *nonceCacheStruct) Stop() {
	close(nc.stopChannel)
}

func newNonceCache(nonceStateTimeout time.Duration, nextNonceCB NextNonceCallback) NonceCache {
	n := &nonceCacheStruct{
		nextNonceBySigner: make(map[tktypes.EthAddress]*cachedNonce),
		nonceStateTimeout: nonceStateTimeout,
		stopChannel:       make(chan struct{}),
		nextNonceCB:       nextNonceCB,
	}
	go n.reap()
	return n
}

type cachedNonce struct {
	nonceMux    sync.Mutex
	signer      tktypes.EthAddress
	value       uint64
	updatedTime time.Time
}

func (nc *nonceCacheStruct) reap() {
	ctx := log.WithLogField(context.Background(), "role", "reaper")
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
			log.L(ctx).Debug("nonce cache reaper completed on ticker")
		}
	}
}

func (nc *nonceCacheStruct) getNextNonceBySigner(signer tktypes.EthAddress) (*cachedNonce, bool) {
	nc.mapMux.Lock()
	defer nc.mapMux.Unlock()
	result, found := nc.nextNonceBySigner[signer]
	return result, found
}

func (nc *nonceCacheStruct) setNextNonceBySigner(signer tktypes.EthAddress, record *cachedNonce) {
	nc.mapMux.Lock()
	defer nc.mapMux.Unlock()
	nc.nextNonceBySigner[signer] = record
}

// Declare an intent to assign a nonce.
// This will ensure that we have a fresh copy of the nonce in memory so that
// the caller can be sure that the nonce assignment step will not suffer the latency of reading the database or calling
// out to the block chain node
// It is the callers responsibility to call `Complete` on the returned object
// The nonce cache for the given signing address is guaranteed not to be reaped after IntentToAssignNonce returns and before `complete`
// NOTE:  multiple readers can hold intents to assign concurrently so the nonce is not actually assigned at this point
//
//	nonce assignment itself is protected by a mutex so only one reader can assign at a time but thanks to the pre intent declaration, the assignment is quick
func (nc *nonceCacheStruct) IntentToAssignNonce(ctx context.Context, signer tktypes.EthAddress) (NonceAssignmentIntent, error) {

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

			nextNonce, err := nc.nextNonceCB(ctx, signer)
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
		addr:        signer,
		locked:      false,
		completed:   false,
		cachedNonce: cachedNonceRecord,
		nonceCache:  nc,
	}, nil
}

func (i *nonceAssignmentIntent) Address() tktypes.EthAddress {
	return i.addr
}

type nonceAssignmentIntent struct {
	addr         tktypes.EthAddress
	locked       bool
	completed    bool
	cachedNonce  *cachedNonce
	nonceCache   *nonceCacheStruct
	initialValue uint64
}

// AssignNextNonce returns the next nonce to be used by the caller and obtains a lock on the nonce
// the caller is responsible for calling Complete or Rollback when they are confident that they will or will not use that nonce
// (i.e. typically just after a database transaction has been committed or rolled back)
// This means that any other callers will be blocked until the current caller calls Complete or Rollback
// if there is a need to obtain multiple nonces on the same signing address as part of the same database transaction,
// then a single NonceAssigmentIntent shoudld be shared and AssignNextNonce should be called
// multiple times on that single intent
// It is invalid to call AssignNextNonce after calling Complete or Rollback
func (i *nonceAssignmentIntent) AssignNextNonce(ctx context.Context) (uint64, error) {
	if i.completed {
		return 0, errors.New("nonceAssignmentIntent already completed") //TODO
	}
	if !i.locked {
		i.cachedNonce.nonceMux.Lock()
		//once we have the lock, take a copy of the first value we see so that we can roll back to it if needed
		i.initialValue = i.cachedNonce.value
		i.locked = true
	}
	value := i.cachedNonce.value
	i.cachedNonce.value = i.cachedNonce.value + 1
	return value, nil
}

func (i *nonceAssignmentIntent) Complete(ctx context.Context) {
	//If we never took the lock or if we have already completed, then this is a no-op
	if !i.completed && i.locked {
		i.cachedNonce.updatedTime = time.Now()
		i.cachedNonce.nonceMux.Unlock()
	}
	if !i.completed {
		i.nonceCache.reaperLock.RUnlock()
	}
	i.completed = true

}

// If Rollback is called after a Complete or another Rollback, it will be a no-op
// thus it is safe to defer Rollback as soon as you have the intent
func (i *nonceAssignmentIntent) Rollback(ctx context.Context) {

	//unlock rollback to previous value

	//If we never took the lock or if we have already completed, then this is a no-op
	if !i.completed && i.locked {
		i.cachedNonce.value = i.initialValue
		i.cachedNonce.nonceMux.Unlock()
	}
	if !i.completed {
		i.nonceCache.reaperLock.RUnlock()
	}
	i.completed = true

}
