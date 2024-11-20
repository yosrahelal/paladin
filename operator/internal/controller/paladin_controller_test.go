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

package controller

import (
	"context"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1alpha1 "github.com/kaleido-io/paladin/operator/api/v1alpha1"
	"github.com/kaleido-io/paladin/operator/pkg/config"
)

var _ = Describe("Paladin Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default", // TODO(user):Modify as needed
		}
		node := &corev1alpha1.Paladin{
			ObjectMeta: metav1.ObjectMeta{
				Name:      resourceName,
				Namespace: "default",
			},
		}
		BeforeEach(func() {
			By("creating the custom resource for the Kind Node")
			err := k8sClient.Get(ctx, typeNamespacedName, node)
			if err != nil && errors.IsNotFound(err) {
				resource := &corev1alpha1.Paladin{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: corev1alpha1.PaladinSpec{
						Database: corev1alpha1.Database{
							Mode:          "sidecarPostgres",
							MigrationMode: "auto",
						},
						BesuNode: "node1",
						SecretBackedSigners: []corev1alpha1.SecretBackedSigner{
							{
								Name:   "signer-1",
								Secret: "node1.keys",
								Type:   "autoHDWallet",
							},
						},
						Transports: []corev1alpha1.TransportConfig{
							{
								Name: "grpc",
								Plugin: corev1alpha1.PluginConfig{
									Type:    "c-shared",
									Library: "/app/transports/libgrpc.so",
								},
								Ports: []corev1.ServicePort{
									{
										Name:     "transport-grpc",
										Port:     9000,
										Protocol: corev1.ProtocolTCP,
									},
								},
								ConfigJSON: `{"port": 9000,"address": "0.0.0.0"}`,
							},
						},
						Domains: []corev1alpha1.DomainReference{
							{
								LabelReference: corev1alpha1.LabelReference{
									LabelSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{
											"paladin.io/domain-name": "noto",
										},
									},
								},
							},
						},
						Registries: []corev1alpha1.RegistryReference{
							{
								LabelReference: corev1alpha1.LabelReference{
									LabelSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{
											"paladin.io/registry-name": "evm-registry",
										},
									},
								},
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			resource := &corev1alpha1.Paladin{}

			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance Node")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			cfg := &config.Config{
				Paladin: config.Template{
					Labels: map[string]string{
						"env":  "production",
						"tier": "backend",
					},
				},
			}
			controllerReconciler := &PaladinReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				config: cfg,
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// TODO(user): Add more specific assertions depending on your controller's reconciliation logic.
			// Example: If you expect a certain status condition after reconciliation, verify it here.
		})
	})
})

func TestPaladin_GetLabels(t *testing.T) {
	// Mock configuration
	config := config.Config{
		Paladin: config.Template{
			Labels: map[string]string{
				"env":  "production",
				"tier": "backend",
			},
		},
	}

	// Initialize PaladinReconciler with mock config
	r := &PaladinReconciler{}
	r.config = &config

	// Mock Paladin node
	node := &corev1alpha1.Paladin{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
		},
	}

	// Extra labels
	extraLabels := map[string]string{
		"version": "v1",
	}

	// Call getLabels
	labels := r.getLabels(node, extraLabels)

	// Assertions
	expectedLabels := map[string]string{
		"app":     "paladin-test-node",
		"env":     "production",
		"tier":    "backend",
		"version": "v1",
	}

	assert.Equal(t, expectedLabels, labels, "labels should match expected labels")
}

// package controllers

// import (
// 	"context"
// 	"fmt"
// 	"testing"

// 	"github.com/stretchr/testify/assert"
// 	corev1 "k8s.io/api/core/v1"
// 	"k8s.io/apimachinery/pkg/types"
// 	"sigs.k8s.io/controller-runtime/pkg/client/fake"

// 	corev1alpha1 "path/to/your/api/v1alpha1"
// 	"path/to/your/pldconf"
// )

func TestGeneratePaladinAuthConfig(t *testing.T) {
	tests := []struct {
		name     string
		node     *corev1alpha1.Paladin
		secret   *corev1.Secret
		wantErr  bool
		expected *pldconf.PaladinConfig
	}{
		{
			name: "Valid AuthConfig with secret",
			node: &corev1alpha1.Paladin{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-node",
					Namespace: "default",
				},
				Spec: corev1alpha1.PaladinSpec{
					AuthConfig: &corev1alpha1.AuthConfig{
						AuthMethod: corev1alpha1.AuthMethodSecret,
						AuthSecret: &corev1alpha1.AuthSecret{Name: "test-secret"},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"username": []byte("testuser"),
					"password": []byte("testpass"),
				},
			},
			wantErr: false,
			expected: &pldconf.PaladinConfig{
				Blockchain: pldconf.EthClientConfig{
					HTTP: pldconf.HTTPClientConfig{
						Auth: pldconf.HTTPBasicAuthConfig{
							Username: "testuser",
							Password: "testpass",
						},
					},
					WS: pldconf.WSClientConfig{
						HTTPClientConfig: pldconf.HTTPClientConfig{
							Auth: pldconf.HTTPBasicAuthConfig{
								Username: "testuser",
								Password: "testpass",
							},
						},
					},
				},
			},
		},
		{
			name: "Secret not found",
			node: &corev1alpha1.Paladin{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-node",
					Namespace: "default",
				},
				Spec: corev1alpha1.PaladinSpec{
					AuthConfig: &corev1alpha1.AuthConfig{
						AuthMethod: corev1alpha1.AuthMethodSecret,
						AuthSecret: &corev1alpha1.AuthSecret{Name: "test-secret"},
					},
				},
			},
			secret:  nil,
			wantErr: true,
		},
		{
			name: "Missing AuthSecret",
			node: &corev1alpha1.Paladin{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-node",
					Namespace: "default",
				},
				Spec: corev1alpha1.PaladinSpec{
					AuthConfig: &corev1alpha1.AuthConfig{
						AuthMethod: corev1alpha1.AuthMethodSecret,
					},
				},
			},
			secret:  nil,
			wantErr: true,
		},
		{
			name: "Secret with no data",
			node: &corev1alpha1.Paladin{
				Spec: corev1alpha1.PaladinSpec{
					AuthConfig: &corev1alpha1.AuthConfig{
						AuthMethod: corev1alpha1.AuthMethodSecret,
						AuthSecret: &corev1alpha1.AuthSecret{Name: "empty-secret"},
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "empty-secret",
					Namespace: "default",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fake client and populate it with the secret if provided
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)
			_ = corev1alpha1.AddToScheme(scheme)
			ctx := context.TODO()

			client := fake.NewClientBuilder().WithScheme(scheme).Build()
			if tt.secret != nil {
				err := client.Create(ctx, tt.secret)
				require.NoError(t, err)
			}

			reconciler := &PaladinReconciler{
				Client: client,
			}

			// Call the method under test
			pldConf := &pldconf.PaladinConfig{}
			err := reconciler.generatePaladinAuthConfig(ctx, tt.node, pldConf)

			// Verify the results
			if tt.wantErr {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				require.NoError(t, err, "Did not expect an error but got one")
				assert.Equal(t, tt.expected.Blockchain.HTTP.Auth, pldConf.Blockchain.HTTP.Auth, "HTTP Auth mismatch")
				assert.Equal(t, tt.expected.Blockchain.WS.Auth, pldConf.Blockchain.WS.Auth, "WS Auth mismatch")
			}
		})
	}
}
