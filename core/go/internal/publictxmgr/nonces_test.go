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
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntentToAssignNonce(t *testing.T) {
	ctx := context.Background()
	nonceCache := newNonceCacheForTesting(t)
	defer nonceCache.stop()
	callbackHasBeenCalled := false
	intent, err := nonceCache.IntentToAssignNonce(ctx, "0xabcd", func(ctx context.Context, signer string) (uint64, error) {
		callbackHasBeenCalled = true
		return uint64(42), nil
	})
	require.NoError(t, err)
	assert.True(t, callbackHasBeenCalled)
	intent.Complete(ctx)

	//Check that the reapear lock is in a state where the reaper can grab it
	gotLock := nonceCache.reaperLock.TryLock()
	assert.True(t, gotLock)
	if gotLock {
		nonceCache.reaperLock.Unlock()
	}
}

func TestAssignNonce(t *testing.T) {
	ctx := context.Background()
	nonceCache := newNonceCacheForTesting(t)
	defer nonceCache.stop()
	callbackHasBeenCalled := false
	callback := func(ctx context.Context, signer string) (uint64, error) {
		callbackHasBeenCalled = true
		return uint64(42), nil
	}
	intent, err := nonceCache.IntentToAssignNonce(ctx, "0xabcd", callback)
	require.NoError(t, err)
	assert.True(t, callbackHasBeenCalled)

	nextNonce, err := intent.AssignNextNonce(ctx)
	require.NoError(t, err)

	assert.Equal(t, uint64(42), nextNonce)
	intent.Complete(ctx)

	callbackHasBeenCalled = false

	intent, err = nonceCache.IntentToAssignNonce(ctx, "0xabcd", callback)
	require.NoError(t, err)
	assert.False(t, callbackHasBeenCalled)

	nextNonce, err = intent.AssignNextNonce(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(43), nextNonce)
	intent.Complete(ctx)

	//Check that the reapear lock is in a state where the reaper can grab it
	gotLock := nonceCache.reaperLock.TryLock()
	assert.True(t, gotLock)
	if gotLock {
		nonceCache.reaperLock.Unlock()
	}

}

func TestIntentToAssignNonceRollbackNoAssign(t *testing.T) {
	ctx := context.Background()
	nonceCache := newNonceCacheForTesting(t)
	defer nonceCache.stop()
	callbackHasBeenCalled := false
	callback := func(ctx context.Context, signer string) (uint64, error) {
		callbackHasBeenCalled = true
		return uint64(42), nil
	}
	intent, err := nonceCache.IntentToAssignNonce(ctx, "0xabcd", callback)
	require.NoError(t, err)
	assert.True(t, callbackHasBeenCalled)
	intent.Rollback(ctx)

	//check that the nonce is still in memory and if assigned, we get the correct nonce
	callbackHasBeenCalled = false
	intent, err = nonceCache.IntentToAssignNonce(ctx, "0xabcd", callback)
	require.NoError(t, err)
	assert.False(t, callbackHasBeenCalled)

	nextNonce, err := intent.AssignNextNonce(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(42), nextNonce)
	intent.Complete(ctx)

	//Check that the reapear lock is in a state where the reaper can grab it
	gotLock := nonceCache.reaperLock.TryLock()
	assert.True(t, gotLock)
	if gotLock {
		nonceCache.reaperLock.Unlock()
	}
}

func TestIntentToAssignNonceCompleteNoAssign(t *testing.T) {
	ctx := context.Background()
	nonceCache := newNonceCacheForTesting(t)
	defer nonceCache.stop()
	callbackHasBeenCalled := false
	callback := func(ctx context.Context, signer string) (uint64, error) {
		callbackHasBeenCalled = true
		return uint64(42), nil
	}
	intent, err := nonceCache.IntentToAssignNonce(ctx, "0xabcd", callback)
	require.NoError(t, err)
	assert.True(t, callbackHasBeenCalled)
	intent.Complete(ctx)

	callbackHasBeenCalled = false
	intent, err = nonceCache.IntentToAssignNonce(ctx, "0xabcd", callback)
	require.NoError(t, err)
	assert.False(t, callbackHasBeenCalled)

	nextNonce, err := intent.AssignNextNonce(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(42), nextNonce)
	intent.Complete(ctx)

	//Check that the reapear lock is in a state where the reaper can grab it
	gotLock := nonceCache.reaperLock.TryLock()
	assert.True(t, gotLock)
	if gotLock {
		nonceCache.reaperLock.Unlock()
	}
}

func TestAssignNonceMultipleNonces(t *testing.T) {
	ctx := context.Background()
	nonceCache := newNonceCacheForTesting(t)
	defer nonceCache.stop()
	callback := func(ctx context.Context, signer string) (uint64, error) {
		return uint64(42), nil
	}
	intent, err := nonceCache.IntentToAssignNonce(ctx, "0xabcd", callback)
	require.NoError(t, err)

	nextNonce, err := intent.AssignNextNonce(ctx)
	require.NoError(t, err)

	assert.Equal(t, uint64(42), nextNonce)
	nextNonce, err = intent.AssignNextNonce(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(43), nextNonce)
	nextNonce, err = intent.AssignNextNonce(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(44), nextNonce)

	intent.Complete(ctx)

	intent, err = nonceCache.IntentToAssignNonce(ctx, "0xabcd", callback)
	require.NoError(t, err)

	nextNonce, err = intent.AssignNextNonce(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(45), nextNonce)
	intent.Complete(ctx)

	//Check that the reapear lock is in a state where the reaper can grab it
	gotLock := nonceCache.reaperLock.TryLock()
	assert.True(t, gotLock)
	if gotLock {
		nonceCache.reaperLock.Unlock()
	}

}

func TestAssignNonceRollback(t *testing.T) {
	ctx := context.Background()
	nonceCache := newNonceCacheForTesting(t)
	defer nonceCache.stop()
	callbackHasBeenCalled := false
	callback := func(ctx context.Context, signer string) (uint64, error) {
		callbackHasBeenCalled = true
		return uint64(42), nil
	}
	intent, err := nonceCache.IntentToAssignNonce(ctx, "0xabcd", callback)
	require.NoError(t, err)
	assert.True(t, callbackHasBeenCalled)

	nextNonce, err := intent.AssignNextNonce(ctx)
	require.NoError(t, err)

	assert.Equal(t, uint64(42), nextNonce)
	intent.Rollback(ctx)

	callbackHasBeenCalled = false

	intent, err = nonceCache.IntentToAssignNonce(ctx, "0xabcd", callback)
	require.NoError(t, err)
	assert.False(t, callbackHasBeenCalled)

	nextNonce, err = intent.AssignNextNonce(ctx)
	require.NoError(t, err)
	//should get 42 as before given that the previous assignment got rolled back
	assert.Equal(t, uint64(42), nextNonce)
	intent.Complete(ctx)

	//Check that the reapear lock is in a state where the reaper can grab it
	gotLock := nonceCache.reaperLock.TryLock()
	assert.True(t, gotLock)
	if gotLock {
		nonceCache.reaperLock.Unlock()
	}
}

func TestAssignNonceMultipleNoncesRollback(t *testing.T) {
	ctx := context.Background()
	nonceCache := newNonceCacheForTesting(t)
	defer nonceCache.stop()
	callback := func(ctx context.Context, signer string) (uint64, error) {
		return uint64(42), nil
	}
	intent, err := nonceCache.IntentToAssignNonce(ctx, "0xabcd", callback)
	require.NoError(t, err)

	nextNonce, err := intent.AssignNextNonce(ctx)
	require.NoError(t, err)

	assert.Equal(t, uint64(42), nextNonce)
	nextNonce, err = intent.AssignNextNonce(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(43), nextNonce)
	nextNonce, err = intent.AssignNextNonce(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(44), nextNonce)

	intent.Rollback(ctx)

	intent, err = nonceCache.IntentToAssignNonce(ctx, "0xabcd", callback)
	require.NoError(t, err)

	nextNonce, err = intent.AssignNextNonce(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(42), nextNonce)
	intent.Complete(ctx)

	//Check that the reapear lock is in a state where the reaper can grab it
	gotLock := nonceCache.reaperLock.TryLock()
	assert.True(t, gotLock)
	if gotLock {
		nonceCache.reaperLock.Unlock()
	}
}

func TestAssignNonceAfterCompleteFail(t *testing.T) {
	ctx := context.Background()
	nonceCache := newNonceCacheForTesting(t)
	defer nonceCache.stop()
	callback := func(ctx context.Context, signer string) (uint64, error) {
		return uint64(42), nil
	}
	intent, err := nonceCache.IntentToAssignNonce(ctx, "0xabcd", callback)
	require.NoError(t, err)

	nextNonce, err := intent.AssignNextNonce(ctx)
	require.NoError(t, err)

	assert.Equal(t, uint64(42), nextNonce)
	intent.Complete(ctx)

	_, err = intent.AssignNextNonce(ctx)
	assert.Error(t, err)

	//Check that the reapear lock is in a state where the reaper can grab it
	gotLock := nonceCache.reaperLock.TryLock()
	assert.True(t, gotLock)
	if gotLock {
		nonceCache.reaperLock.Unlock()
	}
}

func TestAssignNonceAfterRollbackFail(t *testing.T) {
	ctx := context.Background()
	nonceCache := newNonceCacheForTesting(t)
	defer nonceCache.stop()
	callback := func(ctx context.Context, signer string) (uint64, error) {
		return uint64(42), nil
	}
	intent, err := nonceCache.IntentToAssignNonce(ctx, "0xabcd", callback)
	require.NoError(t, err)

	nextNonce, err := intent.AssignNextNonce(ctx)
	require.NoError(t, err)

	assert.Equal(t, uint64(42), nextNonce)
	intent.Rollback(ctx)

	_, err = intent.AssignNextNonce(ctx)
	assert.Error(t, err)

	//Check that the reapear lock is in a state where the reaper can grab it
	gotLock := nonceCache.reaperLock.TryLock()
	assert.True(t, gotLock)
	if gotLock {
		nonceCache.reaperLock.Unlock()
	}
}

func TestAssignNonceMultiThreaded(t *testing.T) {
	ctx := context.Background()
	nonceCache := newNonceCacheForTesting(t)
	firstNonce := uint64(42)
	itterations := 100
	threads := 100
	rollbacks := 0
	results := make([][]uint64, threads)
	for i := 0; i < threads; i++ {
		results[i] = make([]uint64, itterations)
	}

	callbackCalled := 0
	callback := func(ctx context.Context, signer string) (uint64, error) {
		callbackCalled++
		return firstNonce, nil
	}
	doneIt := make(chan struct{}, threads)
	doIt := func(threadNumber int) {
		for itteration := 0; itteration < itterations; itteration++ {

			intent, err := nonceCache.IntentToAssignNonce(ctx, "0xabcd", callback)
			require.NoError(t, err)
			nextNonce, err := intent.AssignNextNonce(ctx)
			require.NoError(t, err)
			if rand.Intn(10) == 9 {
				//rollback on average 10% of the time
				results[threadNumber][itteration] = 1 // 1 is a special value meaning rolledback
				rollbacks++
				intent.Rollback(ctx)
			} else {
				results[threadNumber][itteration] = nextNonce
				intent.Complete(ctx)
			}
		}
		doneIt <- struct{}{}
	}

	for thread := 0; thread < threads; thread++ {
		go doIt(thread)
	}
	threadsDone := 0
	for {
		<-doneIt
		threadsDone++
		if threadsDone == threads {
			break
		}
	}

	highestNonce := firstNonce + (uint64(itterations) * uint64(threads)) - 1 - uint64(rollbacks)

	//we should have a non gapless set of results and within a given thread, they should be in order
	haveSeenFirstNonce := false
	haveSeenHighestNonce := false
	seen := make([]bool, itterations*threads)
	for threadNumber, threadResults := range results {
		previousNonce := firstNonce - 1
		for itterationNumber, itterationResult := range threadResults {
			if itterationResult != 1 { //wasn't one of the random rollbacks
				assert.Greater(t, itterationResult, previousNonce, "nonce %d out of order - not greater than %d on thread %d itteration %d ", itterationResult, previousNonce, threadNumber, itterationNumber)
				assert.False(t, seen[itterationResult-firstNonce], "nonce %d used twice on thread %d itteration %d ", itterationResult, threadNumber, itterationNumber)
				seen[itterationResult-firstNonce] = true
				if itterationResult == firstNonce {
					haveSeenFirstNonce = true
				}
				if itterationResult == highestNonce {
					haveSeenHighestNonce = true
				}
			}
		}
	}
	//given that all nonces are unique and are greater or equal to the first nonce,
	// if we have seen the first and highest nonce then it must be gapless
	assert.True(t, haveSeenFirstNonce)
	assert.True(t, haveSeenHighestNonce)
	assert.Equal(t, 1, callbackCalled)

	//Check that the reapear lock is in a state where the reaper can grab it
	gotLock := nonceCache.reaperLock.TryLock()
	assert.True(t, gotLock)
	if gotLock {
		nonceCache.reaperLock.Unlock()
	}
}

func TestAssignNonceMultiThreadedMultiSigningAddresses(t *testing.T) {
	tests := []struct {
		name                        string
		numSigningAddresses         int
		numThreadsPerSigningAddress int
		numItterationsPerThread     int
	}{
		{
			name:                        "10 signing addresses, 10 threads per signing address, 1000 itterations per thread",
			numSigningAddresses:         10,
			numThreadsPerSigningAddress: 10,
			numItterationsPerThread:     1000,
		},
		{
			name:                        "2 signing addresses, 100 threads per signing address, 1000 itterations per thread",
			numSigningAddresses:         2,
			numThreadsPerSigningAddress: 100,
			numItterationsPerThread:     1000,
		},
		{
			name:                        "100 signing addresses, 2 threads per signing address, 1000 itterations per thread",
			numSigningAddresses:         100,
			numThreadsPerSigningAddress: 2,
			numItterationsPerThread:     1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			ctx := context.Background()
			nonceCache := newNonceCacheForTesting(t)
			firstNonce := uint64(42)

			numSigningAddresses := tt.numSigningAddresses
			numThreadsPerSigningAddress := tt.numThreadsPerSigningAddress
			numItterationsPerThread := tt.numItterationsPerThread

			//generate a random hex string for each signing address
			signingAddresses := make([]string, numSigningAddresses)
			for i := 0; i < numSigningAddresses; i++ {
				signingAddresses[i] = tktypes.RandHex(32)
			}

			// we are going to keep a count of how many rollbacks there were for each signing address
			//so that we can calculate which nonce number we expect to get up to per signign address
			rollbacks := make([]int32, numSigningAddresses)

			//create a 3 dimensional matrix to store the results
			results := make([][][]uint64, numSigningAddresses)
			for s := 0; s < numSigningAddresses; s++ {
				results[s] = make([][]uint64, numThreadsPerSigningAddress)
				for t := 0; t < numThreadsPerSigningAddress; t++ {
					results[s][t] = make([]uint64, numItterationsPerThread)
				}
			}

			//assert that that callback is only called once per signing address
			callbackCalled := make(map[string]bool)
			callback := func(ctx context.Context, signer string) (uint64, error) {
				assert.False(t, callbackCalled[signer])
				callbackCalled[signer] = true
				return firstNonce, nil
			}

			// inner function to run through a number of itterations on a single thread
			runItterationsForThread := func(threadNumber int, signingAddressIndex int, signingAddress string) {
				for itteration := 0; itteration < numItterationsPerThread; itteration++ {
					intent, err := nonceCache.IntentToAssignNonce(ctx, signingAddress, callback)
					defer intent.Rollback(ctx)
					require.NoError(t, err)
					nextNonce, err := intent.AssignNextNonce(ctx)
					require.NoError(t, err)
					if rand.Intn(10) == 9 {
						//rollback on average 10% of the time
						results[signingAddressIndex][threadNumber][itteration] = 1 // 1 is a special value meaning rolledback
						atomic.AddInt32(&rollbacks[signingAddressIndex], 1)
						intent.Rollback(ctx)
					} else {
						results[signingAddressIndex][threadNumber][itteration] = nextNonce
						intent.Complete(ctx)
					}
				}
			}

			//	function to start a number of threads for a given signing address and wait for each of them to complete
			runThreadsForSigningAddress := func(signingAddressIndex int, signingAddress string) {
				var wg sync.WaitGroup
				wg.Add(numThreadsPerSigningAddress)
				for thread := 0; thread < numThreadsPerSigningAddress; thread++ {
					go func() {
						runItterationsForThread(thread, signingAddressIndex, signingAddress)
						wg.Done()
					}()
				}
				wg.Wait()
			}

			var wg sync.WaitGroup
			wg.Add(numSigningAddresses)
			for signingAddressIndex, signingAddress := range signingAddresses {
				go func() {
					runThreadsForSigningAddress(signingAddressIndex, signingAddress)
					wg.Done()
				}()
			}
			wg.Wait()

			//all done, now analyze the results
			for signingAddressNumber, signingAddressResults := range results {
				highestNonce := firstNonce + (uint64(numItterationsPerThread) * uint64(numThreadsPerSigningAddress)) - 1 - uint64(rollbacks[signingAddressNumber])
				//we should have a non gapless set of results and within a given thread, they should be in order
				haveSeenFirstNonce := false
				haveSeenHighestNonce := false
				seen := make([]bool, numItterationsPerThread*numThreadsPerSigningAddress)

				for threadNumber, threadResults := range signingAddressResults {
					previousNonce := firstNonce - 1
					for itterationNumber, itterationResult := range threadResults {
						if itterationResult != 1 { //wasn't one of the random rollbacks
							assert.Greater(t, itterationResult, previousNonce, "nonce %d out of order - not greater than %d on signing address %d thread %d itteration %d ", itterationResult, signingAddressNumber, previousNonce, threadNumber, itterationNumber)
							assert.False(t, seen[itterationResult-firstNonce], "nonce %d used twice on signing address %d thread %d itteration %d ", itterationResult, signingAddressNumber, threadNumber, itterationNumber)
							seen[itterationResult-firstNonce] = true
							if itterationResult == firstNonce {
								haveSeenFirstNonce = true
							}
							if itterationResult == highestNonce {
								haveSeenHighestNonce = true
							}
							previousNonce = itterationResult
						}
					}
				}
				//given that all nonces are unique and are greater or equal to the first nonce,
				// if we have seen the first and highest nonce then it must be gapless
				assert.True(t, haveSeenFirstNonce, "did not see first nonce %d for signing address %d", firstNonce, signingAddressNumber)
				assert.True(t, haveSeenHighestNonce, "did not see highest %d nonce for signing address %d", highestNonce, signingAddressNumber)
				assert.True(t, callbackCalled[signingAddresses[signingAddressNumber]], "callback was not called for signing address %d", signingAddressNumber)
			}
			//Check that the reapear lock is in a state where the reaper can grab it
			gotLock := nonceCache.reaperLock.TryLock()
			assert.True(t, gotLock)
			if gotLock {
				nonceCache.reaperLock.Unlock()
			}
		})
	}
}

func newNonceCacheForTesting(t *testing.T) *nonceCacheStruct {
	nonceCache := newNonceCache(100000 * time.Millisecond)
	return nonceCache.(*nonceCacheStruct)
}

func assertCacheCanBeReaped(t *testing.T, ctx context.Context, nonceCache *nonceCacheStruct) {

}
