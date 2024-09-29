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
	"encoding/json"
	"fmt"

	pldconfig "github.com/kaleido-io/paladin/core/pkg/config"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	yaml "sigs.k8s.io/yaml/goyaml.v3"

	corev1alpha1 "github.com/kaleido-io/paladin/api/v1alpha1"
	"github.com/kaleido-io/paladin/pkg/config"
)

// NodeReconciler reconciles a Node object
type NodeReconciler struct {
	client.Client
	config *config.Config
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=core.paladin.io,resources=nodes,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core.paladin.io,resources=nodes/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=core.paladin.io,resources=nodes/finalizers,verbs=update

// Reconcile implements the logic when a Node resource is created, updated, or deleted
func (r *NodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Generate a name for the Paladin resources
	name := generateName(req.Name)
	namespace := req.Namespace

	// Fetch the Node instance
	var node corev1alpha1.Node
	if err := r.Get(ctx, req.NamespacedName, &node); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Node resource deleted, deleting related resources")
			r.deleteService(ctx, namespace, name)
			r.deleteStatefulSet(ctx, namespace, name)
			r.deleteConfigMap(ctx, namespace, name)

			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get Node resource")
		return ctrl.Result{}, err
	}

	if _, err := r.createConfigMap(ctx, &node, namespace, name); err != nil {
		log.Error(err, "Failed to create Paladin configMap")
		return ctrl.Result{}, err
	}
	log.Info("Created Paladin ConfigMap", "Name", name)

	if _, err := r.createService(ctx, namespace, name); err != nil {
		log.Error(err, "Failed to create Paladin Node")
		return ctrl.Result{}, err
	}
	log.Info("Created Paladin Service", "Name", name)

	ss, err := r.createStatefulSet(ctx, namespace, name)
	if err != nil {
		log.Error(err, "Failed to create Paladin Node")
		return ctrl.Result{}, err
	}
	log.Info("Created Paladin StatefulSet", "Name", ss.Name, "Namespace", ss.Namespace)

	// TODO: Update the Node status
	// node.Status.Name = ss.GetName()
	// node.Status.Namespace = ss.GetNamespace()
	// if err := r.Status().Update(ctx, &node); err != nil {
	// 	log.Error(err, "Failed to update Node status")
	// 	return ctrl.Result{}, err
	// }

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Load the controller configuration
	config, err := config.LoadConfig() // Load the config from file
	if err != nil {
		return err
	}
	r.config = config

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha1.Node{}).
		Complete(r)
}

func (r *NodeReconciler) createStatefulSet(ctx context.Context, namespace, name string) (*appsv1.StatefulSet, error) {
	statefulSet := r.generateStatefulSetTemplate(namespace, name)

	// Check if the StatefulSet already exists, create if not
	var foundStatefulSet appsv1.StatefulSet
	if err := r.Get(ctx, types.NamespacedName{Name: statefulSet.Name, Namespace: statefulSet.Namespace}, &foundStatefulSet); err != nil && errors.IsNotFound(err) {
		err = r.Create(ctx, statefulSet)
		if err != nil {
			return statefulSet, err
		}
	} else if err != nil {
		return statefulSet, err
	}
	return statefulSet, nil

}

func (r *NodeReconciler) generateStatefulSetTemplate(namespace, name string) *appsv1.StatefulSet {
	// Define the StatefulSet to run Paladin using the ConfigMap
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      r.getLabels(name),
			Annotations: r.config.Paladin.Annotations,
		},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: r.getLabels(name),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: r.getLabels(name),
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            name,
							Image:           r.config.Paladin.Image, // Use the image from the config
							ImagePullPolicy: corev1.PullIfNotPresent,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      name,
									MountPath: "/app/config/config.paladin.json",
									SubPath:   "config.paladin.json",
									ReadOnly:  true,
								},
							},
							Args: []string{
								"/app/config/config.paladin.json",
								"testbed",
								"--logtostderr=true",
								"--v=4",
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "http",
									ContainerPort: 8080,
									Protocol:      corev1.ProtocolTCP,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: name,
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: name,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *NodeReconciler) createConfigMap(ctx context.Context, node *corev1alpha1.Node, namespace, name string) (*corev1.ConfigMap, error) {
	configMap, err := r.generateConfigMapTemplate(node, namespace, name)
	if err != nil {
		return nil, err
	}

	var foundConfigMap corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Name: configMap.Name, Namespace: configMap.Namespace}, &foundConfigMap); err != nil && errors.IsNotFound(err) {
		err = r.Create(ctx, configMap)
		if err != nil {
			return configMap, err
		}
	} else if err != nil {
		return configMap, err
	}
	return configMap, nil
}

// generatePaladinConfigMapTemplate generates a ConfigMap for the Paladin configuration
func (r *NodeReconciler) generateConfigMapTemplate(node *corev1alpha1.Node, namespace, name string) (*corev1.ConfigMap, error) {
	pldConfigYAML, err := generatePaladinConfig(node)
	if err != nil {
		return nil, err
	}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    r.getLabels(name),
		},
		Data: map[string]string{
			"config.paladin.yaml": pldConfigYAML,
		},
	}, nil
}

// generatePaladinConfig converts the Node CR spec to a Paladin JSON configuration
func generatePaladinConfig(node *corev1alpha1.Node) (string, error) {
	var pldConf pldconfig.PaladinConfig
	if node.Spec.PaladinConfigYAML != nil {
		err := yaml.Unmarshal([]byte(*node.Spec.PaladinConfigYAML), &pldConf)
		if err != nil {
			return "", fmt.Errorf("paladinConfigYAML is invalid: %s", err)
		}
	}
	// TODO: All the things you can ask the operator to help with to avoid you building the config from scratch
	b, _ := json.Marshal(&pldConf)
	return string(b), nil
}

func (r *NodeReconciler) createService(ctx context.Context, namespace, name string) (*corev1.Service, error) {
	svc := r.generateServiceTemplate(namespace, name)

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

// generateServiceTemplate generates a ConfigMap for the Paladin configuration
func (r *NodeReconciler) generateServiceTemplate(namespace, name string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    r.getLabels(name),
		},
		Spec: corev1.ServiceSpec{
			Selector: r.getLabels(name),
			// TODO: Complete the ServiceSpec (e.g., ports, type, etc.)
			// It will most likely get generated from the config
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       8080,
					TargetPort: intstr.FromInt(8080),
					Protocol:   corev1.ProtocolTCP,
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		},
	}
}

func (r *NodeReconciler) getLabels(name string) map[string]string {
	l := make(map[string]string, len(r.config.Paladin.Labels))
	l["app"] = generateName(name)

	for k, v := range r.config.Paladin.Labels {
		l[k] = v
	}
	return l
}

// generateName generates a name for the Paladin resources based on the Node name.
// this is for generating unique names for the resources
func generateName(n string) string {
	return fmt.Sprintf("paladin-%s", n)
}

func (r *NodeReconciler) deleteStatefulSet(ctx context.Context, namespace, name string) error {
	var foundStatefulSet appsv1.StatefulSet
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &foundStatefulSet)
	if err == nil {
		return r.Delete(ctx, &foundStatefulSet)
	}
	return nil

}

func (r *NodeReconciler) deleteConfigMap(ctx context.Context, namespace, name string) error {
	var foundConfigMap corev1.ConfigMap
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &foundConfigMap)
	if err == nil {
		return r.Delete(ctx, &foundConfigMap)
	}
	return err
}

func (r *NodeReconciler) deleteService(ctx context.Context, namespace, name string) error {

	var foundSvc corev1.Service
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &foundSvc)
	if err == nil {
		return r.Delete(ctx, &foundSvc)
	}
	return err
}
