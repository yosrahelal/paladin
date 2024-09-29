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
	"encoding/hex"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

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

	_ /* configSum */, _, err := r.createConfigSecret(ctx, &node, namespace, name)
	if err != nil {
		log.Error(err, "Failed to create Besu config secret")
		return ctrl.Result{}, err
	}
	log.Info("Created Besu config secret", "Name", name)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *BesuReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha1.Besu{}).
		Complete(r)
}

func (r *BesuReconciler) createConfigSecret(ctx context.Context, node *corev1alpha1.Besu, namespace, name string) (string, *corev1.Secret, error) {
	configSum, configSecret, err := r.generateConfigSecret(ctx, node, namespace, name)
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

func (r *BesuReconciler) generateConfigSecret(ctx context.Context, node *corev1alpha1.Besu, namespace, name string) (string, *corev1.Secret, error) {
	besuConfigTOML, err := r.generateBesuConfig(ctx, node, namespace, name)
	if err != nil {
		return "", nil, err
	}

	configSum := md5.New()
	configSum.Write([]byte(besuConfigTOML))
	configSumHex := hex.EncodeToString(configSum.Sum(nil))
	return configSumHex,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				Labels:    r.getLabels(name),
			},
			StringData: map[string]string{
				"config.besu.toml": besuConfigTOML,
			},
		},
		nil
}

// generateBesuConfig converts the Besu CR spec to a Besu TOML configuration
func (r *BesuReconciler) generateBesuConfig(ctx context.Context, node *corev1alpha1.Besu, namespace, name string) (string, error) {
	var tomlConfig map[string]any

	if node.Spec.Config != nil {
		if err := toml.Unmarshal([]byte(*node.Spec.Config), &tomlConfig); err != nil {
			return "", fmt.Errorf("failed to parse supplied Besu config as TOML: %s", err)
		}
	}

	// We load the genesis CR to find out what nodes are the genesis nodes of the network
	// and use those as our bootnodes.
	// Note there is NO SUPPORT in this basic dev-only operator for Besu for handling the
	// case where these initial nodes no longer exist.

	// Set up the networking, as that's always in our control (we wire it up to the service)
	tomlConfig["rpc-http-host"] = "0.0.0.0"
	tomlConfig["rpc-http-port"] = "8545"
	tomlConfig["rpc-ws-host"] = "0.0.0.0"
	tomlConfig["rpc-ws-port"] = "8546"

	sb := new(strings.Builder)
	_ = toml.NewEncoder(sb).Encode(tomlConfig)
	return sb.String(), nil
}

// generateBesuName generates a name for the Besu resources based on the Besu name.
// this is for generating unique names for the resources
func generateBesuName(n string) string {
	return fmt.Sprintf("besu-%s", n)
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
