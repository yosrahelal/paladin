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

package keymanager

import (
	"context"
	"sync"

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/core/pkg/persistence"

	"github.com/kaleido-io/paladin/toolkit/pkg/cache"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/rpcserver"
)

type keyManager struct {
	bgCtx context.Context

	conf            *pldconf.KeyManagerConfig
	rpcModule       *rpcserver.RPCModule
	identifierCache cache.Cache[string, *components.KeyMappingWithPath]
	verifierCache   cache.Cache[string, *components.KeyVerifier]
	walletsOrdered  []*wallet
	walletsByName   map[string]*wallet

	allocLock        sync.Mutex
	allocPathsLocked map[string]*keyResolutionContext

	p persistence.Persistence
}

func NewKeyManager(bgCtx context.Context, conf *pldconf.KeyManagerConfig) components.KeyManager {
	return &keyManager{
		bgCtx:            bgCtx,
		conf:             conf,
		identifierCache:  cache.NewCache[string, *components.KeyMappingWithPath](&conf.IdentifierCache, &pldconf.KeyManagerDefaults.IdentifierCache),
		verifierCache:    cache.NewCache[string, *components.KeyVerifier](&conf.VerifierCache, &pldconf.KeyManagerDefaults.VerifierCache),
		allocPathsLocked: make(map[string]*keyResolutionContext),
		walletsByName:    make(map[string]*wallet),
	}
}

func (km *keyManager) PreInit(pic components.PreInitComponents) (*components.ManagerInitResult, error) {
	return &components.ManagerInitResult{
		RPCModules: []*rpcserver.RPCModule{km.rpcModule},
	}, nil
}

func (km *keyManager) PostInit(c components.AllComponents) error {
	km.p = c.Persistence()

	for _, walletConf := range km.conf.Wallets {
		w, err := km.newWallet(km.bgCtx, walletConf)
		if err != nil {
			return err
		}
		if km.walletsByName[w.name] != nil {
			return i18n.NewError(km.bgCtx, msgs.MsgKeyManagerDuplicateName, w.name)
		}
		km.walletsByName[w.name] = w
		km.walletsOrdered = append(km.walletsOrdered, w)
	}

	return nil
}

func (km *keyManager) Start() error {
	return nil
}

func (km *keyManager) Stop() {
}

func (km *keyManager) Sign(ctx context.Context, mapping *components.KeyMappingAndVerifier, algorithm, payloadType string, payload []byte) ([]byte, error) {
	w, err := km.getWalletByName(ctx, mapping.Wallet)
	if err != nil {
		return nil, err
	}
	return w.sign(ctx, mapping, algorithm, payloadType, payload)
}

func (km *keyManager) lockPathOrGetOwner(krc *keyResolutionContext, path string) *keyResolutionContext {
	km.allocLock.Lock()
	defer km.allocLock.Unlock()
	existingLock := km.allocPathsLocked[path]
	if existingLock != nil {
		return existingLock
	}
	km.allocPathsLocked[path] = krc
	return nil
}

func (km *keyManager) lockPath(krc *keyResolutionContext, path string) error {
	ctx := krc.ctx
	for {
		lockingKRC := km.lockPathOrGetOwner(krc, path)
		if lockingKRC == nil {
			log.L(ctx).Debugf("key resolution context %s locked path %s", krc.id, path)
			return nil
		}
		// There is contention on this path - wait until the lock is released, and try to get it again
		log.L(ctx).Debugf("key resolution context %s locking on %s for path %s", krc.id, lockingKRC.id, path)
		select {
		case <-lockingKRC.done:
			log.L(ctx).Debugf("key resolution context %s unlocked by %s for path %s", krc.id, lockingKRC.id, path)
		case <-ctx.Done():
			log.L(ctx).Debugf("key resolution context %s cancelled while waiting unlocked by %s for path %s", krc.id, lockingKRC.id, path)
			return i18n.NewError(ctx, msgs.MsgContextCanceled)
		}
	}
}

func (km *keyManager) unlockPaths(krc *keyResolutionContext, paths map[string]bool) {
	km.allocLock.Lock()
	defer km.allocLock.Unlock()

	// We will have locks on all the parent paths
	for path := range paths {
		log.L(krc.ctx).Debugf("key resolution context %s unlocked path %s", krc.id, path)
		delete(km.allocPathsLocked, path)
	}
}
