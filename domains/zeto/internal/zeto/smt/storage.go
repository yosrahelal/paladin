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

package smt

import (
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
)

type statesStorage struct {
	smtName string
}

func (s *statesStorage) GetRootNodeIndex() (core.NodeIndex, error) {
	root := core.SMTRoot{
		Name: s.smtName,
	}
	err := s.p.DB().Table(core.TreeRootsTable).First(&root).Error
	if err == gorm.ErrRecordNotFound {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	idx, err := node.NewNodeIndexFromHex(root.RootIndex)
	return idx, err
}

func (s *statesStorage) UpsertRootNodeIndex(root core.NodeIndex) error {
	return upsertRootNodeIndex(s.p.DB(), s.smtName, root)
}

func (s *statesStorage) GetNode(ref core.NodeIndex) (core.Node, error) {
	return getNode(s.p.DB(), s.nodesTableName, ref)
}

func (s *statesStorage) InsertNode(n core.Node) error {
	return insertNode(s.p.DB(), s.nodesTableName, n)
}

func (s *statesStorage) BeginTx() (core.Transaction, error) {
	return &sqlTxStorage{
		tx:             s.p.DB().Begin(),
		smtName:        s.smtName,
		nodesTableName: s.nodesTableName,
	}, nil
}

type sqlTxStorage struct {
	tx             *gorm.DB
	smtName        string
	nodesTableName string
}

func (b *sqlTxStorage) UpsertRootNodeIndex(root core.NodeIndex) error {
	return upsertRootNodeIndex(b.tx, b.smtName, root)
}

func (b *sqlTxStorage) GetNode(ref core.NodeIndex) (core.Node, error) {
	return getNode(b.tx, b.nodesTableName, ref)
}

func (b *sqlTxStorage) InsertNode(n core.Node) error {
	return insertNode(b.tx, b.nodesTableName, n)
}

func (b *sqlTxStorage) Commit() error {
	return b.tx.Commit().Error
}

func (b *sqlTxStorage) Rollback() error {
	return b.tx.Rollback().Error
}

func (m *statesStorage) Close() {
	m.p.Close()
}
