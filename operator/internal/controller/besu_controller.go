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
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
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

	_ /* configSum */, _, err = r.createConfigSecret(ctx, &node)
	if err != nil {
		log.Error(err, "Failed to create Besu config secret")
		return ctrl.Result{}, err
	}
	log.Info("Created Besu config secret", "Name", name)

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

func (r *BesuReconciler) createConfigSecret(ctx context.Context, node *corev1alpha1.Besu) (string, *corev1.Secret, error) {
	configSum, configSecret, err := r.generateConfigSecret(ctx, node)
	if err != nil {
		return "", nil, err
	}

	var foundConfigSecret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: configSecret.Name, Namespace: configSecret.Namespace}, &foundConfigSecret); err != nil && errors.IsNotFound(err) {
		err = r.Create(ctx, configSecret)
		if err != nil {
			return "", nil, err
		}
	} else if err != nil {
		return "", nil, err
	} else {
		foundConfigSecret.StringData = configSecret.StringData
		return configSum, &foundConfigSecret, r.Update(ctx, &foundConfigSecret)
	}
	return configSum, configSecret, nil
}

func (r *BesuReconciler) generateConfigSecret(ctx context.Context, node *corev1alpha1.Besu) (string, *corev1.Secret, error) {
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
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      generateBesuName(node.Name),
				Namespace: node.Namespace,
				Labels:    r.getLabels(node.Name),
			},
			StringData: map[string]string{
				"config.besu.toml":  besuConfigTOML,
				"static-nodes.json": staticNodesJSON,
			},
		},
		nil
}

// generateBesuConfigTOML converts the Besu CR spec to a Besu TOML configuration
func (r *BesuReconciler) generateBesuConfigTOML(node *corev1alpha1.Besu) (string, error) {
	tomlConfig := map[string]any{}

	if node.Spec.Config != nil {
		if err := toml.Unmarshal([]byte(*node.Spec.Config), &tomlConfig); err != nil {
			return "", fmt.Errorf("failed to parse supplied Besu config as TOML: %s", err)
		}
	}

	// Set up the networking, as that's always in our control (we wire it up to the service)
	tomlConfig["rpc-http-host"] = "0.0.0.0"
	tomlConfig["rpc-http-port"] = "8545"
	tomlConfig["rpc-ws-host"] = "0.0.0.0"
	tomlConfig["rpc-ws-port"] = "8546"
	tomlConfig["p2p-host"] = "0.0.0.0"
	tomlConfig["p2p-port"] = "30303"

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
		enodeURLs = append(enodeURLs, fmt.Sprintf("enode://%s@%s.%s.svc.cluster.local:30303",
			nodeIdSecret.Data["id"], generateBesuName(nodeName), node.Namespace))
	}

	// Need a consistent hash
	sort.Strings(enodeURLs)

	b, _ := json.MarshalIndent(enodeURLs, "", "  ")
	return string(b), nil
}

// generateBesuName generates a name for the Besu resources based on the Besu name.
// this is for generating unique names for the resources
func generateBesuName(n string) string {
	return fmt.Sprintf("besu-%s", n)
}

func generateBesuIDSecretName(n string) string {
	return fmt.Sprintf("besu-%s-id", n)
}

func (r *BesuReconciler) getLabels(name string, extraLabels ...map[string]string) map[string]string {
	l := make(map[string]string, len(r.config.Besu.Labels))
	l["app"] = generateBesuName(name)

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
		err = r.Get(ctx, types.NamespacedName{Name: generateBesuGenesisConfigMapName(node.Spec.Genesis), Namespace: node.Namespace}, &cm)
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
			Labels:    r.getLabels(node.Name),
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
