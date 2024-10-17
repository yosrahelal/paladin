/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"context"

	_ "embed"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldclient"
)

const node1HttpURL = "http://127.0.0.1:31548"
const node2HttpURL = "http://127.0.0.1:31648"
const node3HttpURL = "http://127.0.0.1:31748"

var _ = Describe("controller", Ordered, func() {
	BeforeAll(func() {
	})

	AfterAll(func() {
	})

	Context("Noto domain verification", func() {
		It("start up the node", func() {
			ctx := context.Background()

			_, err := pldclient.New().HTTP(ctx, &pldconf.HTTPClientConfig{
				URL: "http://127.0.0.1:31548",
			})
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

		})
	})
})
