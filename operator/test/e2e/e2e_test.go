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
	"fmt"
	"os/exec"
	"time"

	_ "embed"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/kaleido-io/paladin/operator/test/utils"
	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/rpcclient"
)

const namespace = "paladin-e2e" // if changed, must also change the YAML

//go:embed e2e_single_node_besugenesis.yaml
var e2eSingleNodeBesuGenesisYAML string

//go:embed e2e_single_node_besu.yaml
var e2eSingleNodeBesuYAML string

//go:embed e2e_single_node_paladin_postgres.yaml
var e2eSingleNodePaladinPostgresYAML string

func startPaladinOperator() {
	var controllerPodName string
	var err error

	// projectimage stores the name of the image used in the example
	var projectimage = "paladin-operator:latest"

	By("building the manager(Operator) image")
	cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", projectimage))
	_, err = utils.Run(cmd)
	ExpectWithOffset(0, err).NotTo(HaveOccurred())

	By("ensuring the kind cluster is up")
	cmd = exec.Command("make", "kind-start")
	_, err = utils.Run(cmd)
	ExpectWithOffset(0, err).NotTo(HaveOccurred())

	By("ensuring the latest built images are available in the kind cluster")
	cmd = exec.Command("make", "kind-promote")
	_, err = utils.Run(cmd)
	ExpectWithOffset(0, err).NotTo(HaveOccurred())

	By("loading the the manager(Operator) image on Kind")
	err = utils.LoadImageToKindClusterWithName(projectimage)
	ExpectWithOffset(0, err).NotTo(HaveOccurred())

	By("ensuring the latest CRDs are applied with kustomize before doing a helm install")
	cmd = exec.Command("make", "update-crds")
	_, err = utils.Run(cmd)
	ExpectWithOffset(0, err).NotTo(HaveOccurred())

	By("installing via Helm")
	cmd = exec.Command("make", "helm-install",
		fmt.Sprintf("IMG=%s", projectimage),
		fmt.Sprintf("NAMESPACE=%s", namespace),
	)
	_, err = utils.Run(cmd)
	ExpectWithOffset(0, err).NotTo(HaveOccurred())

	By("validating that the controller-manager pod is running as expected")
	verifyControllerUp := func() error {
		// Get pod name

		cmd = exec.Command("kubectl", "get",
			"pods", "-l", "app.kubernetes.io/name=paladin-operator",
			"-o", "go-template={{ range .items }}"+
				"{{ if not .metadata.deletionTimestamp }}"+
				"{{ .metadata.name }}"+
				"{{ \"\\n\" }}{{ end }}{{ end }}",
			"-n", namespace,
		)

		podOutput, err := utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		podNames := utils.GetNonEmptyLines(string(podOutput))
		if len(podNames) != 1 {
			return fmt.Errorf("expect 1 controller pods running, but got %d", len(podNames))
		}
		controllerPodName = podNames[0]
		ExpectWithOffset(1, controllerPodName).Should(ContainSubstring("paladin-operator"))

		// Validate pod status
		cmd = exec.Command("kubectl", "get",
			"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
			"-n", namespace,
		)
		status, err := utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		if string(status) != "Running" {
			return fmt.Errorf("controller pod in %s status", status)
		}
		return nil
	}
	EventuallyWithOffset(0, verifyControllerUp, time.Minute, time.Second).Should(Succeed())
}

var _ = Describe("controller", Ordered, func() {
	BeforeAll(func() {
		By("installing prometheus operator")
		Expect(utils.InstallPrometheusOperator()).To(Succeed())

		By("installing the cert-manager")
		Expect(utils.InstallCertManager()).To(Succeed())

		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, _ = utils.Run(cmd)

		startPaladinOperator()
	})

	AfterAll(func() {
		By("uninstalling the Prometheus manager bundle")
		utils.UninstallPrometheusOperator()

		By("uninstalling the cert-manager bundle")
		utils.UninstallCertManager()

		By("removing manager namespace")
		cmd := exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	Context("Paladin Single Node", func() {
		It("start up the node", func() {
			ctx := context.Background()

			By("creating a genesis CR with a single validator")
			err := utils.KubectlApplyYAML(e2eSingleNodeBesuGenesisYAML)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("creating a Besu node CR")
			err = utils.KubectlApplyYAML(e2eSingleNodeBesuYAML)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("creating a Paladin node CR")
			err = utils.KubectlApplyYAML(e2eSingleNodePaladinPostgresYAML)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("waiting for the Paladin API to become available")
			EventuallyWithOffset(1, func() error {
				rpc, err := rpcclient.NewHTTPClient(ctx, &rpcclient.HTTPConfig{
					URL: "http://127.0.0.1:31548",
				})
				if err != nil {
					return err
				}
				var txs []*ptxapi.Transaction
				return rpc.CallRPC(ctx, &txs, "ptx_queryTransactions", query.NewQueryBuilder().Limit(1).Query(), false)
			}, time.Minute, time.Second).Should(Succeed())

		})
	})
})
