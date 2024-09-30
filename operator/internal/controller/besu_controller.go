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
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/hyperledger/firefly-signer/pkg/secp256k1"
	corev1alpha1 "github.com/kaleido-io/paladin/operator/api/v1alpha1"
	"github.com/kaleido-io/paladin/operator/pkg/config"
	"github.com/pelletier/go-toml/v2"
)

// BesuReconciler reconciles a Besu object
type BesuReconciler struct {
	client.Client
	config *config.Config
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=core.paladin.io,resources=besus,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core.paladin.io,resources=besus/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core.paladin.io,resources=besus/finalizers,verbs=update

// Reconcile implements the logic when a Besu resource is created, updated, or deleted
func (r *BesuReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Generate a name for the Besu resources
	name := generateBesuName(req.Name)
	namespace := req.Namespace

	// Fetch the Besu instance
	var node corev1alpha1.Besu
	if err := r.Get(ctx, req.NamespacedName, &node); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Besu resource deleted, deleting related resources")
			r.deleteService(ctx, namespace, name)
			r.deleteStatefulSet(ctx, namespace, name)
			r.deleteConfigSecret(ctx, namespace, name)

			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get Besu resource")
		return ctrl.Result{}, err
	}

	// We create the identity of the node first, as the genesis controller requires this from
	// the initial validators to build the genesis
	_, err := r.createIdentitySecret(ctx, &node)
	if err != nil {
		log.Error(err, "Failed to create Besu identity secret")
		return ctrl.Result{}, err
	}
	log.Info("Created Besu config secret", "Name", name)

	genesis, err := r.loadGenesis(ctx, &node)
	if err != nil {
		log.Error(err, "Failed to retrieve BesuGenesis")
		return ctrl.Result{}, err
	}
	if genesis == nil {
		log.Info("Waiting for genesis to become available")
		return ctrl.Result{
			// Short retry until we get the genesis
			RequeueAfter: 1 * time.Second,
		}, err
	}

	configSum, _, err := r.createConfigMap(ctx, &node)
	if err != nil {
		log.Error(err, "Failed to create Besu config map")
		return ctrl.Result{}, err
	}
	log.Info("Created Besu config map", "Name", name)

	if _, err := r.createService(ctx, &node, name); err != nil {
		log.Error(err, "Failed to create Besu Service")
		return ctrl.Result{}, err
	}
	log.Info("Created Besu Service", "Name", name)

	if _, err := r.createPDB(ctx, &node, name); err != nil {
		log.Error(err, "Failed to create Besu pod disruption budget")
		return ctrl.Result{}, err
	}
	log.Info("Created Besu pod disruption budget", "Name", name)

	ss, err := r.createStatefulSet(ctx, &node, name, configSum)
	if err != nil {
		log.Error(err, "Failed to create Besu StatefulSet")
		return ctrl.Result{}, err
	}
	log.Info("Created Besu StatefulSet", "Name", ss.Name, "Namespace", ss.Namespace)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *BesuReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Load the controller configuration
	config, err := config.LoadConfig() // Load the config from file
	if err != nil {
		return err
	}
	r.config = config

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha1.Besu{}).
		Complete(r)
}

func (r *BesuReconciler) createConfigMap(ctx context.Context, node *corev1alpha1.Besu) (string, *corev1.ConfigMap, error) {
	configSum, configMap, err := r.generateConfigMap(ctx, node)
	if err != nil {
		return "", nil, err
	}

	var foundConfigMap corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Name: configMap.Name, Namespace: configMap.Namespace}, &foundConfigMap); err != nil && errors.IsNotFound(err) {
		err = r.Create(ctx, configMap)
		if err != nil {
			return "", nil, err
		}
	} else if err != nil {
		return "", nil, err
	} else {
		foundConfigMap.Data = configMap.Data
		return configSum, &foundConfigMap, r.Update(ctx, &foundConfigMap)
	}
	return configSum, configMap, nil
}

func (r *BesuReconciler) generateConfigMap(ctx context.Context, node *corev1alpha1.Besu) (string, *corev1.ConfigMap, error) {
	besuConfigTOML, err := r.generateBesuConfigTOML(node)
	if err != nil {
		return "", nil, err
	}

	staticNodesJSON, err := r.generateStaticNodesJSON(ctx, node)
	if err != nil {
		return "", nil, err
	}

	configSum := md5.New()
	configSum.Write([]byte(besuConfigTOML))
	configSum.Write([]byte(staticNodesJSON))
	configSumHex := hex.EncodeToString(configSum.Sum(nil))
	return configSumHex,
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      generateBesuName(node.Name),
				Namespace: node.Namespace,
				Labels:    r.getLabels(node),
			},
			Data: map[string]string{
				"config.besu.toml":  besuConfigTOML,
				"static-nodes.json": staticNodesJSON,
			},
		},
		nil
}

// generateBesuConfigTOML converts the Besu CR spec to a Besu TOML configuration
func (r *BesuReconciler) generateBesuConfigTOML(node *corev1alpha1.Besu) (string, error) {
	tomlConfig := map[string]any{}

	setIfUnset := func(k string, v any) {
		if _, isSet := tomlConfig[k]; !isSet {
			tomlConfig[k] = v
		}
	}

	if node.Spec.Config != nil {
		if err := toml.Unmarshal([]byte(*node.Spec.Config), &tomlConfig); err != nil {
			return "", fmt.Errorf("failed to parse supplied Besu config as TOML: %s", err)
		}
	}

	// Setup from our mounts
	tomlConfig["node-private-key-file"] = "/nodeid/key"
	tomlConfig["data-path"] = "/data"
	tomlConfig["genesis-file"] = "/genesis/genesis.json"

	// Set up the networking, as that's always in our control (we wire it up to the service)
	comprehensiveRPCSet := []string{"ETH", "NET", "QBFT", "WEB3", "ADMIN", "DEBUG"}
	tomlConfig["rpc-http-enabled"] = true
	tomlConfig["rpc-http-host"] = "0.0.0.0"
	tomlConfig["rpc-http-port"] = "8545"
	setIfUnset("rpc-http-api", comprehensiveRPCSet)
	tomlConfig["rpc-ws-enabled"] = true
	tomlConfig["rpc-ws-host"] = "0.0.0.0"
	tomlConfig["rpc-ws-port"] = "8546"
	setIfUnset("rpc-ws-api", comprehensiveRPCSet)
	tomlConfig["graphql-http-enabled"] = true
	tomlConfig["graphql-http-host"] = "0.0.0.0"
	tomlConfig["graphql-http-port"] = "8547"
	tomlConfig["p2p-host"] = "0.0.0.0"
	tomlConfig["p2p-port"] = "30303"
	setIfUnset("host-allowlist", []string{"*"})

	setIfUnset("logging", "DEBUG")
	setIfUnset("revert-reason-enabled", true)
	setIfUnset("tx-pool", "SEQUENCED")

	// To give a stable network through node restarts we use hostnames in static-nodes.json
	// https://besu.hyperledger.org/24.1.0/public-networks/concepts/node-keys#enode-url
	tomlConfig["discovery-enabled"] = false
	tomlConfig["static-nodes-file"] = "/config/static-nodes.json"
	tomlConfig["Xdns-enabled"] = true
	tomlConfig["Xdns-update-enabled"] = true

	sb := new(strings.Builder)
	_ = toml.NewEncoder(sb).Encode(tomlConfig)
	return sb.String(), nil
}

func (r *BesuReconciler) generateStaticNodesJSON(ctx context.Context, node *corev1alpha1.Besu) (string, error) {

	// Find all node identities with the same genesis
	// We use a label to mark all the secrets that should be node ID
	sameGenesis, _ := labels.NewRequirement("besu-genesis", selection.Equals, []string{node.Spec.Genesis})
	withNodeName, _ := labels.NewRequirement("besu-node-id", selection.Exists, []string{})
	var secrets corev1.SecretList
	if err := r.List(ctx, &secrets, client.InNamespace(node.Namespace), client.MatchingLabelsSelector{
		Selector: labels.NewSelector().Add(*sameGenesis, *withNodeName),
	}); err != nil {
		return "", err
	}

	enodeURLs := []string{}
	for _, nodeIdSecret := range secrets.Items {
		// note it's perfectly fine to include our own node in the static-nodes.json
		nodeName := nodeIdSecret.Labels["besu-node-id"]
		enodeURLs = append(enodeURLs, fmt.Sprintf("enode://%s@%s:30303",
			nodeIdSecret.Data["id"], generateBesuServiceHostname(nodeName, node.Namespace)))
	}

	// Need a consistent hash
	sort.Strings(enodeURLs)

	b, _ := json.MarshalIndent(enodeURLs, "", "  ")
	return string(b), nil
}

func generateBesuServiceHostname(nodeName, namespace string) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local", generateBesuName(nodeName), namespace)
}

// generateBesuName generates a name for the Besu resources based on the Besu name.
// this is for generating unique names for the resources
func generateBesuName(n string) string {
	return fmt.Sprintf("besu-%s", n)
}

func generateBesuPVCName(n string) string {
	return fmt.Sprintf("%s-data", generateBesuName(n))
}

func generateBesuIDSecretName(n string) string {
	return fmt.Sprintf("besu-%s-id", n)
}

func (r *BesuReconciler) getLabels(node *corev1alpha1.Besu, extraLabels ...map[string]string) map[string]string {
	l := make(map[string]string, len(r.config.Besu.Labels))
	l["app"] = generateBesuName(node.Name)

	for k, v := range r.config.Besu.Labels {
		l[k] = v
	}
	for _, e := range extraLabels {
		for k, v := range e {
			l[k] = v
		}
	}
	return l
}

func (r *BesuReconciler) createIdentitySecret(ctx context.Context, node *corev1alpha1.Besu) (*corev1.Secret, error) {
	name := generateBesuIDSecretName(node.Name)

	var idSecret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: node.Namespace}, &idSecret); err != nil && errors.IsNotFound(err) {
		idSecret = *r.generateSecretTemplate(node, name)
		idSecret.Labels["besu-node-id"] = node.Name
		idSecret.Labels["besu-genesis"] = node.Spec.Genesis
		randBytes32 := make([]byte, 32)
		_, _ = rand.Read(randBytes32)
		nodeKey := secp256k1.KeyPairFromBytes(randBytes32)
		idSecret.StringData = map[string]string{
			"key":     hex.EncodeToString(randBytes32),
			"id":      hex.EncodeToString(nodeKey.PublicKeyBytes()),
			"address": nodeKey.Address.String(),
		}
		err = r.Create(ctx, &idSecret)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return &idSecret, nil
}

func (r *BesuReconciler) loadGenesis(ctx context.Context, node *corev1alpha1.Besu) (*corev1alpha1.BesuGenesis, error) {

	// We load the genesis CR definition
	var genesis corev1alpha1.BesuGenesis
	err := r.Get(ctx, types.NamespacedName{Name: node.Spec.Genesis, Namespace: node.Namespace}, &genesis)
	if err == nil {
		// ... and we load the config map which will be generated by the genesis controller once it has read
		// the IDs of any nodes declared in the InitialValidators set (including ours which we just wrote).
		// We do this as we don't want to create the pod until this exits, although we don't use the result directly.
		var cm corev1.ConfigMap
		err = r.Get(ctx, types.NamespacedName{Name: generateBesuGenesisName(node.Spec.Genesis), Namespace: node.Namespace}, &cm)
	}
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &genesis, nil
}

func (r *BesuReconciler) generateSecretTemplate(node *corev1alpha1.Besu, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: node.Namespace,
			Labels:    r.getLabels(node),
		},
	}
}

func (r *BesuReconciler) createStatefulSet(ctx context.Context, node *corev1alpha1.Besu, name, configSum string) (*appsv1.StatefulSet, error) {
	statefulSet := r.generateStatefulSetTemplate(node, name, configSum)

	if err := r.createDataPVC(ctx, node); err != nil {
		return nil, err
	}

	// Check if the StatefulSet already exists, create if not
	var foundStatefulSet appsv1.StatefulSet
	if err := r.Get(ctx, types.NamespacedName{Name: statefulSet.Name, Namespace: statefulSet.Namespace}, &foundStatefulSet); err != nil && errors.IsNotFound(err) {
		err = r.Create(ctx, statefulSet)
		if err != nil {
			return statefulSet, err
		}
	} else if err != nil {
		return statefulSet, err
	} else {
		// Only update safe things
		foundStatefulSet.Spec.Template.Spec.Containers = statefulSet.Spec.Template.Spec.Containers
		foundStatefulSet.Spec.Template.Spec.Volumes = statefulSet.Spec.Template.Spec.Volumes
		foundStatefulSet.Spec.Template.Annotations = statefulSet.Spec.Template.Annotations
		foundStatefulSet.Spec.Template.Labels = statefulSet.Spec.Template.Labels
		// TODO: Other things that can be merged?
		return &foundStatefulSet, r.Update(ctx, &foundStatefulSet)
	}
	return statefulSet, nil

}

func (r *BesuReconciler) createDataPVC(ctx context.Context, node *corev1alpha1.Besu) error {
	pvc := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generateBesuPVCName(node.Name),
			Namespace: node.Namespace,
			Labels:    r.getLabels(node),
		},
		Spec: node.Spec.PVCTemplate,
	}
	pvc.Spec.AccessModes = []corev1.PersistentVolumeAccessMode{
		corev1.ReadWriteOnce,
	}
	if pvc.Spec.Resources.Requests == nil {
		pvc.Spec.Resources.Requests = corev1.ResourceList{}
	}
	if _, resourceSet := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; !resourceSet {
		pvc.Spec.Resources.Requests[corev1.ResourceStorage] = resource.MustParse("1Gi")
	}

	var foundPVC corev1.PersistentVolumeClaim
	if err := r.Get(ctx, types.NamespacedName{Name: pvc.Name, Namespace: pvc.Namespace}, &foundPVC); err != nil && errors.IsNotFound(err) {
		err = r.Create(ctx, &pvc)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}

func (r *BesuReconciler) withStandardAnnotations(annotations map[string]string) map[string]string {
	for k, v := range r.config.Besu.Annotations {
		annotations[k] = v
	}
	return annotations
}

func (r *BesuReconciler) generatePDBTemplate(node *corev1alpha1.Besu, name string) *policyv1.PodDisruptionBudget {
	// We only have once replica per statefulset, so eviction for upgrade makes sense as the default
	return &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: node.Namespace,
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			UnhealthyPodEvictionPolicy: ptrTo(policyv1.AlwaysAllow),
			Selector: &metav1.LabelSelector{
				MatchLabels: r.getLabels(node),
			},
		},
	}
}

func (r *BesuReconciler) createPDB(ctx context.Context, node *corev1alpha1.Besu, name string) (*policyv1.PodDisruptionBudget, error) {
	pdb := r.generatePDBTemplate(node, name)

	var foundPDB policyv1.PodDisruptionBudget
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: pdb.Namespace}, &foundPDB); err != nil && errors.IsNotFound(err) {
		err = r.Create(ctx, pdb)
		if err != nil {
			return pdb, err
		}
	} else if err != nil {
		return nil, err
	}
	return &foundPDB, nil
}

func (r *BesuReconciler) generateStatefulSetTemplate(node *corev1alpha1.Besu, name, configSum string) *appsv1.StatefulSet {
	// Define the StatefulSet to run Besu using the ConfigMap
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: node.Namespace,
			Annotations: r.withStandardAnnotations(map[string]string{
				"kubectl.kubernetes.io/default-container": "besu",
			}),
		},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: r.getLabels(node),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: r.getLabels(node, map[string]string{
						"config-sum": configSum,
					}),
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            "besu",
							Image:           r.config.Besu.Image, // Use the image from the config
							ImagePullPolicy: corev1.PullIfNotPresent,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "config",
									MountPath: "/config",
									ReadOnly:  true,
								},
								{
									Name:      "nodeid",
									MountPath: "/nodeid",
									ReadOnly:  true,
								},
								{
									Name:      "genesis",
									MountPath: "/genesis",
									ReadOnly:  true,
								},
								{
									Name:      "data",
									MountPath: "/data",
								},
							},
							Args: []string{
								"--config-file",
								"/config/config.besu.toml",
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "rpc-http",
									ContainerPort: 8545,
									Protocol:      corev1.ProtocolTCP,
								},
								{
									Name:          "rpc-ws",
									ContainerPort: 8546,
									Protocol:      corev1.ProtocolTCP,
								},
								{
									Name:          "graphql-http",
									ContainerPort: 8547,
									Protocol:      corev1.ProtocolTCP,
								},
								{
									Name:          "p2p-tcp",
									ContainerPort: 30303,
									Protocol:      corev1.ProtocolTCP,
								},
								{
									Name:          "p2p-udp",
									ContainerPort: 30303,
									Protocol:      corev1.ProtocolUDP,
								},
							},
							Env: buildEnv(r.config.Besu.Envs),
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: name,
									},
								},
							},
						},
						{
							Name: "nodeid",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: generateBesuIDSecretName(node.Name),
								},
							},
						},
						{
							Name: "genesis",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: generateBesuGenesisName(node.Spec.Genesis),
									},
								},
							},
						},
						{
							Name: "data",
							VolumeSource: corev1.VolumeSource{
								PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
									ClaimName: generateBesuPVCName(node.Name),
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *BesuReconciler) createService(ctx context.Context, node *corev1alpha1.Besu, name string) (*corev1.Service, error) {
	svc := r.generateServiceTemplate(node, name)

	var foundSvc corev1.Service
	if err := r.Get(ctx, types.NamespacedName{Name: svc.Name, Namespace: svc.Namespace}, &foundSvc); err != nil && errors.IsNotFound(err) {
		err = r.Create(ctx, svc)
		if err != nil {
			return svc, err
		}
	} else if err != nil {
		return svc, err
	}
	return svc, nil
}

// generateServiceTemplate generates a ConfigMap for the Besu configuration
func (r *BesuReconciler) generateServiceTemplate(node *corev1alpha1.Besu, name string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: node.Namespace,
			Labels:    r.getLabels(node),
		},
		Spec: corev1.ServiceSpec{
			Selector: r.getLabels(node),
			Ports: []corev1.ServicePort{
				{
					Name:       "rpc-http",
					Port:       8545,
					TargetPort: intstr.FromInt(8545),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       "rpc-ws",
					Port:       8546,
					TargetPort: intstr.FromInt(8546),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       "graphql-http",
					Port:       8547,
					TargetPort: intstr.FromInt(8547),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       "p2p-tcp",
					Port:       30303,
					TargetPort: intstr.FromInt(30303),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       "p2p-udp",
					Port:       30303,
					TargetPort: intstr.FromInt(30303),
					Protocol:   corev1.ProtocolUDP,
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		},
	}
}

func (r *BesuReconciler) deleteStatefulSet(ctx context.Context, namespace, name string) error {
	var foundStatefulSet appsv1.StatefulSet
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &foundStatefulSet)
	if err == nil {
		return r.Delete(ctx, &foundStatefulSet)
	}
	return nil

}

func (r *BesuReconciler) deleteConfigSecret(ctx context.Context, namespace, name string) error {
	var foundSecret corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &foundSecret)
	if err == nil {
		return r.Delete(ctx, &foundSecret)
	}
	return err
}

func (r *BesuReconciler) deleteService(ctx context.Context, namespace, name string) error {

	var foundSvc corev1.Service
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &foundSvc)
	if err == nil {
		return r.Delete(ctx, &foundSvc)
	}
	return err
}
