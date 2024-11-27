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
	"fmt"
	"testing"

	// . "github.com/onsi/ginkgo/v2"
	// . "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	corev1alpha1 "github.com/kaleido-io/paladin/operator/api/v1alpha1"
	"github.com/kaleido-io/paladin/operator/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// var _ = Describe("Besu Controller", func() {
// 	var (
// 		ctx                context.Context
// 		resourceName       string
// 		namespace          string
// 		typeNamespacedName types.NamespacedName
// 		besu               *corev1alpha1.Besu
// 		besuGenesis        *corev1alpha1.BesuGenesis
// 		genesisConfigMap   *corev1.ConfigMap
// 		besuReconciler     *BesuReconciler
// 	)

// 	BeforeEach(func() {
// 		ctx = context.Background()
// 		resourceName = "test-besu"
// 		namespace = "default"
// 		typeNamespacedName = types.NamespacedName{
// 			Name:      resourceName,
// 			Namespace: namespace,
// 		}

// 		// Initialize BesuGenesis
// 		besuGenesis = &corev1alpha1.BesuGenesis{
// 			ObjectMeta: metav1.ObjectMeta{
// 				Name:      "test-genesis",
// 				Namespace: namespace,
// 			},
// 			Spec: corev1alpha1.BesuGenesisSpec{
// 				Consensus:         "qbft",
// 				InitialValidators: []string{"validator1", "validator2"},
// 			},
// 		}
// 		err := k8sClient.Create(ctx, besuGenesis)
// 		Expect(err).NotTo(HaveOccurred())

// 		genesisConfigMap = &corev1.ConfigMap{
// 			ObjectMeta: metav1.ObjectMeta{
// 				Name:      generateBesuGenesisName(besuGenesis.ObjectMeta.Name),
// 				Namespace: namespace,
// 			},
// 			Data: map[string]string{
// 				"genesis.json": `{"consensus": "qbft"}`,
// 			},
// 		}
// 		err = k8sClient.Create(ctx, genesisConfigMap)
// 		Expect(err).NotTo(HaveOccurred())

// 		// Initialize Besu resource
// 		besu = &corev1alpha1.Besu{
// 			ObjectMeta: metav1.ObjectMeta{
// 				Name:      resourceName,
// 				Namespace: namespace,
// 			},
// 			Spec: corev1alpha1.BesuSpec{
// 				Genesis: besuGenesis.ObjectMeta.Name,
// 			},
// 		}

// 		// Initialize BesuReconciler
// 		cfg := &config.Config{
// 			Besu: config.Template{
// 				Image:           "hyperledger/besu:latest",
// 				ImagePullPolicy: corev1.PullAlways,
// 				Labels: map[string]string{
// 					"env":  "test",
// 					"tier": "backend",
// 				},
// 				Annotations: map[string]string{
// 					"test-annotation": "test",
// 				},
// 				Envs: map[string]string{
// 					"ENV_VAR": "value",
// 				},
// 			},
// 		}
// 		besuReconciler = &BesuReconciler{
// 			Client: k8sClient,
// 			Scheme: clientgoscheme.Scheme,
// 			config: cfg,
// 		}

// 		// Create the Besu custom resource
// 		By("Creating the Besu custom resource")
// 		err = k8sClient.Create(ctx, besu)
// 		Expect(err).NotTo(HaveOccurred())
// 	})

// 	AfterEach(func() {
// 		// Delete the Besu custom resource
// 		By("Deleting the Besu custom resource")
// 		err := k8sClient.Delete(ctx, besu)
// 		Expect(err).NotTo(HaveOccurred())

// 		err = k8sClient.Delete(ctx, besuGenesis)
// 		Expect(err).NotTo(HaveOccurred())

// 		err = k8sClient.Delete(ctx, genesisConfigMap)
// 		Expect(err).NotTo(HaveOccurred())

// 	})

// 	Context("When reconciling a new Besu resource", func() {
// 		It("Should create all necessary Kubernetes resources", func() {
// 			By("Reconciling the Besu resource")
// 			_, err := besuReconciler.Reconcile(ctx, reconcile.Request{
// 				NamespacedName: typeNamespacedName,
// 			})
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Checking if the StatefulSet was created")
// 			statefulSet := &appsv1.StatefulSet{}
// 			err = k8sClient.Get(ctx, types.NamespacedName{
// 				Name:      generateBesuName(resourceName),
// 				Namespace: namespace,
// 			}, statefulSet)
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(statefulSet.Name).To(Equal(generateBesuName(resourceName)))

// 			By("Checking if the Service was created")
// 			service := &corev1.Service{}
// 			err = k8sClient.Get(ctx, types.NamespacedName{
// 				Name:      generateBesuName(resourceName),
// 				Namespace: namespace,
// 			}, service)
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(service.Name).To(Equal(generateBesuName(resourceName)))

// 			By("Checking if the ConfigMap was created")
// 			configMap := &corev1.ConfigMap{}
// 			err = k8sClient.Get(ctx, types.NamespacedName{
// 				Name:      generateBesuName(resourceName),
// 				Namespace: namespace,
// 			}, configMap)
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(configMap.Name).To(Equal(generateBesuName(resourceName)))

// 			By("Checking if the Secret was created")
// 			secret := &corev1.Secret{}
// 			err = k8sClient.Get(ctx, types.NamespacedName{
// 				Name:      generateBesuIDSecretName(resourceName),
// 				Namespace: namespace,
// 			}, secret)
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(secret.Name).To(Equal(generateBesuIDSecretName(resourceName)))

// 			By("Checking if the PodDisruptionBudget was created")
// 			pdb := &policyv1.PodDisruptionBudget{}
// 			err = k8sClient.Get(ctx, types.NamespacedName{
// 				Name:      generateBesuName(resourceName),
// 				Namespace: namespace,
// 			}, pdb)
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(pdb.Name).To(Equal(generateBesuName(resourceName)))
// 		})
// 	})

// 	Context("When updating the Besu resource", func() {
// 		It("Should update the Kubernetes resources accordingly", func() {
// 			By("Reconciling the Besu resource initially")
// 			_, err := besuReconciler.Reconcile(ctx, reconcile.Request{
// 				NamespacedName: typeNamespacedName,
// 			})
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Updating the Besu resource with new configuration")
// 			updatedBesu := &corev1alpha1.Besu{}
// 			err = k8sClient.Get(ctx, typeNamespacedName, updatedBesu)
// 			Expect(err).NotTo(HaveOccurred())
// 			updatedBesu.Spec.Config = ptrToString("[Node]\nDataDir = \"/new-data-dir\"\n")
// 			err = k8sClient.Update(ctx, updatedBesu)
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Reconciling the Besu resource after update")
// 			_, err = besuReconciler.Reconcile(ctx, reconcile.Request{
// 				NamespacedName: typeNamespacedName,
// 			})
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Verifying that the StatefulSet has been updated")
// 			statefulSet := &appsv1.StatefulSet{}
// 			err = k8sClient.Get(ctx, types.NamespacedName{
// 				Name:      generateBesuName(resourceName),
// 				Namespace: namespace,
// 			}, statefulSet)
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(statefulSet.Spec.Template.Annotations).To(HaveKey("core.paladin.io/config-sum"))

// 			By("Verifying that the ConfigMap has been updated")
// 			configMap := &corev1.ConfigMap{}
// 			err = k8sClient.Get(ctx, types.NamespacedName{
// 				Name:      generateBesuName(resourceName),
// 				Namespace: namespace,
// 			}, configMap)
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(configMap.Data["pldconf.besu.toml"]).To(ContainSubstring("/new-data-dir"))
// 		})
// 	})

// 	Context("When deleting a Besu resource", func() {
// 		It("Should clean up all associated resources", func() {
// 			By("Reconciling the Besu resource")
// 			_, err := besuReconciler.Reconcile(ctx, reconcile.Request{
// 				NamespacedName: typeNamespacedName,
// 			})
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Deleting the Besu resource")
// 			err = k8sClient.Delete(ctx, besu)
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Ensuring associated resources are deleted")
// 			Eventually(func() bool {
// 				statefulSet := &appsv1.StatefulSet{}
// 				err = k8sClient.Get(ctx, types.NamespacedName{
// 					Name:      generateBesuName(resourceName),
// 					Namespace: namespace,
// 				}, statefulSet)
// 				return errors.IsNotFound(err)
// 			}, time.Second*5, time.Millisecond*500).Should(BeTrue())

// 			Eventually(func() bool {
// 				service := &corev1.Service{}
// 				err = k8sClient.Get(ctx, types.NamespacedName{
// 					Name:      generateBesuName(resourceName),
// 					Namespace: namespace,
// 				}, service)
// 				return errors.IsNotFound(err)
// 			}, time.Second*5, time.Millisecond*500).Should(BeTrue())

// 			Eventually(func() bool {
// 				configMap := &corev1.ConfigMap{}
// 				err = k8sClient.Get(ctx, types.NamespacedName{
// 					Name:      generateBesuName(resourceName),
// 					Namespace: namespace,
// 				}, configMap)
// 				return errors.IsNotFound(err)
// 			}, time.Second*5, time.Millisecond*500).Should(BeTrue())

// 			Eventually(func() bool {
// 				secret := &corev1.Secret{}
// 				err = k8sClient.Get(ctx, types.NamespacedName{
// 					Name:      generateBesuIDSecretName(resourceName),
// 					Namespace: namespace,
// 				}, secret)
// 				return errors.IsNotFound(err)
// 			}, time.Second*5, time.Millisecond*500).Should(BeTrue())

// 			Eventually(func() bool {
// 				pdb := &policyv1.PodDisruptionBudget{}
// 				err = k8sClient.Get(ctx, types.NamespacedName{
// 					Name:      generateBesuName(resourceName),
// 					Namespace: namespace,
// 				}, pdb)
// 				return errors.IsNotFound(err)
// 			}, time.Second*5, time.Millisecond*500).Should(BeTrue())
// 		})
// 	})

// 	Context("When the Genesis resource is missing", func() {
// 		It("Should set the status to Pending and requeue", func() {
// 			By("Setting a non-existent Genesis in the Besu resource")
// 			besu.Spec.Genesis = "non-existent-genesis"
// 			err := k8sClient.Update(ctx, besu)
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Reconciling the Besu resource")
// 			result, err := besuReconciler.Reconcile(ctx, reconcile.Request{
// 				NamespacedName: typeNamespacedName,
// 			})
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

// 			By("Verifying the status is set to Pending")
// 			updatedBesu := &corev1alpha1.Besu{}
// 			err = k8sClient.Get(ctx, typeNamespacedName, updatedBesu)
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(updatedBesu.Status.Phase).To(Equal(corev1alpha1.StatusPhasePending))
// 		})
// 	})

// 	Context("When failing to create a resource", func() {
// 		It("Should set the status to Failed", func() {
// 			By("Providing invalid Service configuration")
// 			besu.Spec.Service = corev1.ServiceSpec{
// 				Type: corev1.ServiceType("InvalidType"),
// 			}
// 			err := k8sClient.Update(ctx, besu)
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Reconciling the Besu resource")
// 			_, err = besuReconciler.Reconcile(ctx, reconcile.Request{
// 				NamespacedName: typeNamespacedName,
// 			})
// 			Expect(err).To(HaveOccurred())

// 			By("Verifying the status is set to Failed")
// 			updatedBesu := &corev1alpha1.Besu{}
// 			err = k8sClient.Get(ctx, typeNamespacedName, updatedBesu)
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(updatedBesu.Status.Phase).To(Equal(corev1alpha1.StatusPhaseFailed))
// 		})
// 	})

// 	Context("When updating labels and annotations", func() {
// 		It("Should propagate them to associated resources", func() {
// 			By("Reconciling the Besu resource")
// 			_, err := besuReconciler.Reconcile(ctx, reconcile.Request{
// 				NamespacedName: typeNamespacedName,
// 			})
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Updating labels and annotations in the Besu resource")
// 			updatedBesu := &corev1alpha1.Besu{}
// 			err = k8sClient.Get(ctx, typeNamespacedName, updatedBesu)
// 			Expect(err).NotTo(HaveOccurred())
// 			updatedBesu.Labels = map[string]string{
// 				"new-label": "new-value",
// 			}
// 			updatedBesu.Annotations = map[string]string{
// 				"new-annotation": "new-value",
// 			}
// 			err = k8sClient.Update(ctx, updatedBesu)
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Reconciling the Besu resource after label update")
// 			_, err = besuReconciler.Reconcile(ctx, reconcile.Request{
// 				NamespacedName: typeNamespacedName,
// 			})
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Verifying labels are updated on the StatefulSet")
// 			statefulSet := &appsv1.StatefulSet{}
// 			err = k8sClient.Get(ctx, types.NamespacedName{
// 				Name:      generateBesuName(resourceName),
// 				Namespace: namespace,
// 			}, statefulSet)
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(statefulSet.Labels).To(HaveKeyWithValue("new-label", "new-value"))
// 			Expect(statefulSet.Annotations).To(HaveKeyWithValue("new-annotation", "new-value"))
// 		})
// 	})

// 	Context("When ConfigMap data changes", func() {
// 		It("Should trigger a rolling update of the StatefulSet", func() {
// 			By("Reconciling the Besu resource")
// 			_, err := besuReconciler.Reconcile(ctx, reconcile.Request{
// 				NamespacedName: typeNamespacedName,
// 			})
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Simulating a change in ConfigMap data")
// 			configMap := &corev1.ConfigMap{}
// 			err = k8sClient.Get(ctx, types.NamespacedName{
// 				Name:      generateBesuName(resourceName),
// 				Namespace: namespace,
// 			}, configMap)
// 			Expect(err).NotTo(HaveOccurred())
// 			configMap.Data["pldconf.besu.toml"] = "modified data"
// 			err = k8sClient.Update(ctx, configMap)
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Reconciling the Besu resource after ConfigMap change")
// 			_, err = besuReconciler.Reconcile(ctx, reconcile.Request{
// 				NamespacedName: typeNamespacedName,
// 			})
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Verifying the StatefulSet's annotation has been updated")
// 			statefulSet := &appsv1.StatefulSet{}
// 			err = k8sClient.Get(ctx, types.NamespacedName{
// 				Name:      generateBesuName(resourceName),
// 				Namespace: namespace,
// 			}, statefulSet)
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(statefulSet.Spec.Template.Annotations).To(HaveKey("core.paladin.io/config-sum"))
// 		})
// 	})

// 	Context("When the Besu resource specifies custom environment variables", func() {
// 		It("Should set them in the Besu container", func() {
// 			By("Updating the Besu resource with custom environment variables")
// 			updatedBesu := &corev1alpha1.Besu{}
// 			err := k8sClient.Get(ctx, typeNamespacedName, updatedBesu)
// 			Expect(err).NotTo(HaveOccurred())
// 			updatedBesu.Spec.Config = ptrToString("[Node]\nCustomEnvVar = \"custom-value\"\n")
// 			err = k8sClient.Update(ctx, updatedBesu)
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Reconciling the Besu resource")
// 			_, err = besuReconciler.Reconcile(ctx, reconcile.Request{
// 				NamespacedName: typeNamespacedName,
// 			})
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Verifying the environment variables in the StatefulSet")
// 			statefulSet := &appsv1.StatefulSet{}
// 			err = k8sClient.Get(ctx, types.NamespacedName{
// 				Name:      generateBesuName(resourceName),
// 				Namespace: namespace,
// 			}, statefulSet)
// 			Expect(err).NotTo(HaveOccurred())

// 			var besuContainer corev1.Container
// 			for _, container := range statefulSet.Spec.Template.Spec.Containers {
// 				if container.Name == "besu" {
// 					besuContainer = container
// 					break
// 				}
// 			}
// 			Expect(besuContainer.Env).To(ContainElement(corev1.EnvVar{
// 				Name:  "ENV_VAR",
// 				Value: "value",
// 			}))
// 		})
// 	})

// 	Context("When the PersistentVolumeClaim is missing", func() {
// 		It("Should create the PVC and proceed", func() {
// 			By("Reconciling the Besu resource")
// 			_, err := besuReconciler.Reconcile(ctx, reconcile.Request{
// 				NamespacedName: typeNamespacedName,
// 			})
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Deleting the PVC to simulate missing PVC")
// 			pvc := &corev1.PersistentVolumeClaim{}
// 			err = k8sClient.Get(ctx, types.NamespacedName{
// 				Name:      generateBesuPVCName(resourceName),
// 				Namespace: namespace,
// 			}, pvc)
// 			Expect(err).NotTo(HaveOccurred())
// 			err = k8sClient.Delete(ctx, pvc)
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Reconciling the Besu resource after PVC deletion")
// 			_, err = besuReconciler.Reconcile(ctx, reconcile.Request{
// 				NamespacedName: typeNamespacedName,
// 			})
// 			Expect(err).NotTo(HaveOccurred())

// 			By("Verifying the PVC has been recreated")
// 			err = k8sClient.Get(ctx, types.NamespacedName{
// 				Name:      generateBesuPVCName(resourceName),
// 				Namespace: namespace,
// 			}, pvc)
// 			Expect(err).NotTo(HaveOccurred())
// 		})
// 	})
// })

// setupBesuTestReconciler sets up a BesuReconciler for testing
func setupBesuTestReconciler(objs ...runtime.Object) (*BesuReconciler, error) {
	scheme, err := corev1alpha1.SchemeBuilder.Build()
	if err != nil {
		return nil, err
	}

	// Add other necessary schemes
	_ = appsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = policyv1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objs...).Build()

	cfg := &config.Config{
		Besu: config.Template{
			Image:           "hyperledger/besu:latest",
			ImagePullPolicy: corev1.PullAlways,
			Labels:          map[string]string{"test-label": "test"},
			Annotations:     map[string]string{"test-annotation": "test"},
			Envs:            map[string]string{"ENV_VAR": "value"},
			Tolerations:     []corev1.Toleration{},
			Affinity:        &corev1.Affinity{},
			NodeSelector:    map[string]string{},
			SecurityContext: &corev1.SecurityContext{},
		},
	}

	return &BesuReconciler{
		Client: fakeClient,
		config: cfg,
		Scheme: scheme,
	}, nil
}
func TestGenerateBesuConfigTOML(t *testing.T) {
	r, err := setupBesuTestReconciler()
	require.NoError(t, err)

	node := &corev1alpha1.Besu{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-besu",
			Namespace: "default",
		},
		Spec: corev1alpha1.BesuSpec{
			Config: nil,
		},
	}

	tomlConfig, err := r.generateBesuConfigTOML(node)
	require.NoError(t, err)
	assert.Contains(t, tomlConfig, "node-private-key-file")
	assert.Contains(t, tomlConfig, "data-path")
	assert.Contains(t, tomlConfig, "genesis-file")
}
func TestGenerateStaticNodesJSON(t *testing.T) {
	node := &corev1alpha1.Besu{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-besu",
			Namespace: "default",
		},
		Spec: corev1alpha1.BesuSpec{
			Genesis: "test-genesis",
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generateBesuIDSecretName(node.Name),
			Namespace: node.Namespace,
			Labels: map[string]string{
				"besu-node-id": node.Name,
				"besu-genesis": node.Spec.Genesis,
			},
		},
		Data: map[string][]byte{
			"id": []byte("test-node-id"),
		},
	}

	r, err := setupBesuTestReconciler(secret)
	require.NoError(t, err)

	staticNodesJSON, err := r.generateStaticNodesJSON(context.TODO(), node)
	require.NoError(t, err)
	assert.Contains(t, staticNodesJSON, "enode://test-node-id")
}
func TestGenerateBesuServiceHostname(t *testing.T) {
	nodeName := "test-node"
	namespace := "default"

	hostname := generateBesuServiceHostname(nodeName, namespace)
	expectedHostname := fmt.Sprintf("besu-%s.%s.svc.cluster.local", nodeName, namespace)
	assert.Equal(t, expectedHostname, hostname)
}
func TestGenerateBesuName(t *testing.T) {
	name := "test-node"
	expectedName := "besu-test-node"

	generatedName := generateBesuName(name)
	assert.Equal(t, expectedName, generatedName)
}
func TestGenerateBesuPVCName(t *testing.T) {
	name := "test-node"
	expectedPVCName := "besu-test-node-data"

	pvcName := generateBesuPVCName(name)
	assert.Equal(t, expectedPVCName, pvcName)
}
func TestGenerateBesuIDSecretName(t *testing.T) {
	name := "test-node"
	expectedSecretName := "besu-test-node-id"

	secretName := generateBesuIDSecretName(name)
	assert.Equal(t, expectedSecretName, secretName)
}
func TestGetLabels(t *testing.T) {
	r, err := setupBesuTestReconciler()
	require.NoError(t, err)

	node := &corev1alpha1.Besu{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-besu",
			Namespace: "default",
		},
	}

	labels := r.getLabels(node)
	expectedLabels := map[string]string{
		"test-label":                 "test",
		"app.kubernetes.io/name":     generateBesuName(node.Name),
		"app.kubernetes.io/instance": node.Name,
		"app.kubernetes.io/part-of":  "paladin",
	}

	for k, v := range expectedLabels {
		assert.Equal(t, v, labels[k])
	}
}
func TestCreateIdentitySecret(t *testing.T) {
	node := &corev1alpha1.Besu{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-besu",
			Namespace: "default",
		},
		Spec: corev1alpha1.BesuSpec{
			Genesis: "test-genesis",
		},
		Status: corev1alpha1.Status{
			Conditions: []metav1.Condition{},
		},
	}

	r, err := setupBesuTestReconciler()
	require.NoError(t, err)

	secret, err := r.createIdentitySecret(context.TODO(), node)
	require.NoError(t, err)
	require.NotNil(t, secret)
	assert.Equal(t, generateBesuIDSecretName(node.Name), secret.Name)
}
func TestLoadGenesis(t *testing.T) {
	node := &corev1alpha1.Besu{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-besu",
			Namespace: "default",
		},
		Spec: corev1alpha1.BesuSpec{
			Genesis: "test-genesis",
		},
	}

	genesis := &corev1alpha1.BesuGenesis{
		ObjectMeta: metav1.ObjectMeta{
			Name:      node.Spec.Genesis,
			Namespace: node.Namespace,
		},
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generateBesuGenesisName(node.Spec.Genesis),
			Namespace: node.Namespace,
		},
	}

	r, err := setupBesuTestReconciler(genesis, configMap)
	require.NoError(t, err)

	loadedGenesis, err := r.loadGenesis(context.TODO(), node)
	require.NoError(t, err)
	require.NotNil(t, loadedGenesis)
	assert.Equal(t, node.Spec.Genesis, loadedGenesis.Name)
}
func TestGenerateSecretTemplate(t *testing.T) {
	r, err := setupBesuTestReconciler()
	require.NoError(t, err)

	node := &corev1alpha1.Besu{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-besu",
			Namespace: "default",
		},
	}

	secretName := "test-secret"
	secret := r.generateSecretTemplate(node, secretName)

	assert.Equal(t, secretName, secret.Name)
	assert.Equal(t, node.Namespace, secret.Namespace)
	assert.Equal(t, r.getLabels(node), secret.Labels)
}

func TestCreateStatefulSet(t *testing.T) {
	node := &corev1alpha1.Besu{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-besu",
			Namespace: "default",
		},
		Spec: corev1alpha1.BesuSpec{
			Genesis:     "test-genesis",
			PVCTemplate: corev1.PersistentVolumeClaimSpec{},
		},
		Status: corev1alpha1.Status{
			Conditions: []metav1.Condition{},
		},
	}

	r, err := setupBesuTestReconciler()
	require.NoError(t, err)

	statefulSet, err := r.createStatefulSet(context.TODO(), node, generateBesuName(node.Name), "dummy-config-sum")
	require.NoError(t, err)
	require.NotNil(t, statefulSet)
	assert.Equal(t, generateBesuName(node.Name), statefulSet.Name)
}
func TestCreateDataPVC(t *testing.T) {
	node := &corev1alpha1.Besu{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-besu",
			Namespace: "default",
		},
		Spec: corev1alpha1.BesuSpec{
			PVCTemplate: corev1.PersistentVolumeClaimSpec{
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceStorage: resource.MustParse("2Gi"),
					},
				},
			},
		},
		Status: corev1alpha1.Status{
			Conditions: []metav1.Condition{},
		},
	}

	r, err := setupBesuTestReconciler()
	require.NoError(t, err)

	err = r.createDataPVC(context.TODO(), node)
	require.NoError(t, err)

	pvc := &corev1.PersistentVolumeClaim{}
	err = r.Get(context.TODO(), types.NamespacedName{
		Name:      generateBesuPVCName(node.Name),
		Namespace: node.Namespace,
	}, pvc)
	require.NoError(t, err)
	assert.Equal(t, resource.MustParse("2Gi"), pvc.Spec.Resources.Requests[corev1.ResourceStorage])
}
func TestWithStandardAnnotations(t *testing.T) {
	r, err := setupBesuTestReconciler()
	require.NoError(t, err)

	annotations := map[string]string{
		"custom-annotation": "custom-value",
	}

	result := r.withStandardAnnotations(annotations)

	expectedAnnotations := map[string]string{
		"custom-annotation": "custom-value",
		"test-annotation":   "test",
	}

	assert.Equal(t, expectedAnnotations, result)
}
func TestGeneratePDBTemplate(t *testing.T) {
	r, err := setupBesuTestReconciler()
	require.NoError(t, err)

	node := &corev1alpha1.Besu{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-besu",
			Namespace: "default",
		},
	}

	name := generateBesuName(node.Name)
	pdb := r.generatePDBTemplate(node, name)

	assert.Equal(t, name, pdb.Name)
	assert.Equal(t, node.Namespace, pdb.Namespace)
	require.NotNil(t, pdb.Spec.Selector)
}
func TestCreatePDB(t *testing.T) {
	node := &corev1alpha1.Besu{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-besu",
			Namespace: "default",
		},
		Status: corev1alpha1.Status{
			Conditions: []metav1.Condition{},
		},
	}

	r, err := setupBesuTestReconciler()
	require.NoError(t, err)

	name := generateBesuName(node.Name)
	pdb, err := r.createPDB(context.TODO(), node, name)
	require.NoError(t, err)
	require.NotNil(t, pdb)
	assert.Equal(t, name, pdb.Name)
}
func TestGenerateStatefulSetTemplate(t *testing.T) {
	r, err := setupBesuTestReconciler()
	require.NoError(t, err)

	node := &corev1alpha1.Besu{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-besu",
			Namespace: "default",
		},
		Spec: corev1alpha1.BesuSpec{
			Genesis: "test-genesis",
		},
	}

	name := generateBesuName(node.Name)
	statefulSet := r.generateStatefulSetTemplate(node, name, "dummy-config-sum")

	assert.Equal(t, name, statefulSet.Name)
	assert.Equal(t, node.Namespace, statefulSet.Namespace)
	assert.Equal(t, r.getLabels(node), statefulSet.Labels)
	require.NotNil(t, statefulSet.Spec.Template.Spec.Containers)
}
func TestBesuCreateService(t *testing.T) {
	node := &corev1alpha1.Besu{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-besu",
			Namespace: "default",
		},
		Spec: corev1alpha1.BesuSpec{
			Service: corev1.ServiceSpec{},
		},
		Status: corev1alpha1.Status{
			Conditions: []metav1.Condition{},
		},
	}

	r, err := setupBesuTestReconciler()
	require.NoError(t, err)

	name := generateBesuName(node.Name)
	service, err := r.createService(context.TODO(), node, name)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.Equal(t, name, service.Name)
}
func TestGenerateServiceTemplate(t *testing.T) {
	r, err := setupBesuTestReconciler()
	require.NoError(t, err)

	node := &corev1alpha1.Besu{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-besu",
			Namespace: "default",
		},
		Spec: corev1alpha1.BesuSpec{
			Service: corev1.ServiceSpec{},
		},
	}

	name := generateBesuName(node.Name)
	service := r.generateServiceTemplate(node, name)

	assert.Equal(t, name, service.Name)
	assert.Equal(t, node.Namespace, service.Namespace)
	assert.Equal(t, r.getLabels(node), service.Spec.Selector)
	assert.NotEmpty(t, service.Spec.Ports)
}

// Helper functions
func ptrToString(s string) *string {
	return &s
}
