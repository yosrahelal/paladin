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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	pldconfig "github.com/kaleido-io/paladin/core/pkg/config"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/core/pkg/signer/signerapi"
	"github.com/tyler-smith/go-bip39"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
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
			r.deleteConfigSecret(ctx, namespace, name)

			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get Node resource")
		return ctrl.Result{}, err
	}

	configSum, _, err := r.createConfigSecret(ctx, &node, namespace, name)
	if err != nil {
		log.Error(err, "Failed to create Paladin config secret")
		return ctrl.Result{}, err
	}
	log.Info("Created Paladin config secret", "Name", name)

	if _, err := r.createService(ctx, namespace, name); err != nil {
		log.Error(err, "Failed to create Paladin Node")
		return ctrl.Result{}, err
	}
	log.Info("Created Paladin Service", "Name", name)

	ss, err := r.createStatefulSet(ctx, &node, namespace, name, configSum)
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

func (r *NodeReconciler) createStatefulSet(ctx context.Context, node *corev1alpha1.Node, namespace, name, configSum string) (*appsv1.StatefulSet, error) {
	statefulSet := r.generateStatefulSetTemplate(namespace, name, configSum)

	if node.Spec.Database.Mode == corev1alpha1.DBMode_SidecarPostgres {
		// Earlier processing responsible for ensuring this is non-nil
		r.addPostgresSidecar(statefulSet, *node.Spec.Database.PasswordSecret)
		if err := r.createPostgresPVC(ctx, node, namespace, name); err != nil {
			return nil, err
		}
	}

	r.addKeystoreSecretMounts(statefulSet, node.Spec.SecretBackedSigners)

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
		// TODO: Other things that can be merged? Labels? Annotations?
		return &foundStatefulSet, r.Update(ctx, &foundStatefulSet)
	}
	return statefulSet, nil

}

func (r *NodeReconciler) withStandardAnnotations(annotations map[string]string) map[string]string {
	for k, v := range r.config.Paladin.Annotations {
		annotations[k] = v
	}
	return annotations
}

func buildEnv(envMaps ...map[string]string) []corev1.EnvVar {
	envVars := make([]corev1.EnvVar, 0)
	for _, envMap := range envMaps {
		for k, v := range envMap {
			envVars = append(envVars, corev1.EnvVar{
				Name:  k,
				Value: v,
			})
		}
	}
	return envVars
}

func (r *NodeReconciler) generateStatefulSetTemplate(namespace, name, configSum string) *appsv1.StatefulSet {
	// Define the StatefulSet to run Paladin using the ConfigMap
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: r.withStandardAnnotations(map[string]string{
				"kubectl.kubernetes.io/default-container": "paladin",
				"paladin.io/config-sum":                   configSum,
			}),
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
							Name:            "paladin",
							Image:           r.config.Paladin.Image, // Use the image from the config
							ImagePullPolicy: corev1.PullIfNotPresent,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "config",
									MountPath: "/app/config",
									ReadOnly:  true,
								},
							},
							Args: []string{
								"/app/config/config.paladin.yaml",
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
							Env: buildEnv(r.config.Paladin.Envs),
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: name,
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *NodeReconciler) addPostgresSidecar(ss *appsv1.StatefulSet, passwordSecret string) {
	ss.Spec.Template.Spec.Containers = append(ss.Spec.Template.Spec.Containers, corev1.Container{
		Name:            "postgres",
		Image:           r.config.Postgres.Image, // Use the image from the config
		ImagePullPolicy: corev1.PullIfNotPresent,
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "pgdata",
				MountPath: "/pgdata",
			},
		},
		Ports: []corev1.ContainerPort{
			{
				Name:          "postgres",
				ContainerPort: 5432,
				Protocol:      corev1.ProtocolTCP,
			},
		},
		Env: append([]corev1.EnvVar{
			{
				Name: "POSTGRES_PASSWORD",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: passwordSecret,
						},
						Key: "password",
					},
				},
			},
		}, buildEnv(r.config.Postgres.Envs, map[string]string{
			"PGDATA": "/pgdata",
		})...),
	})
	ss.Spec.Template.Spec.Volumes = append(ss.Spec.Template.Spec.Volumes, corev1.Volume{
		Name: "pgdata",
		VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: fmt.Sprintf("%s-pgdata", ss.Name),
			},
		},
	})
}

func (r *NodeReconciler) createPostgresPVC(ctx context.Context, node *corev1alpha1.Node, namespace, name string) error {
	pvc := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-pgdata", name),
			Namespace: namespace,
			Labels:    r.getLabels(name),
		},
		Spec: node.Spec.Database.PVCTemplate,
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

func (r *NodeReconciler) addKeystoreSecretMounts(ss *appsv1.StatefulSet, signers []corev1alpha1.SecretBackedSigner) {
	paladinContainer := ss.Spec.Template.Spec.Containers[0]
	for _, s := range signers {
		paladinContainer.VolumeMounts = append(paladinContainer.VolumeMounts, corev1.VolumeMount{
			Name:      fmt.Sprintf("keystore-%s", s.Name),
			MountPath: fmt.Sprintf("/keystores/%s", s.Name),
		})
		ss.Spec.Template.Spec.Volumes = append(ss.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: fmt.Sprintf("keystore-%s", s.Name),
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: s.Secret,
				},
			},
		})
	}
}

func (r *NodeReconciler) createConfigSecret(ctx context.Context, node *corev1alpha1.Node, namespace, name string) (string, *corev1.Secret, error) {
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

// generatePaladinConfigMapTemplate generates a ConfigMap for the Paladin configuration
func (r *NodeReconciler) generateConfigSecret(ctx context.Context, node *corev1alpha1.Node, namespace, name string) (string, *corev1.Secret, error) {
	pldConfigYAML, err := r.generatePaladinConfig(ctx, node, namespace, name)
	if err != nil {
		return "", nil, err
	}
	configSum := md5.New()
	configSum.Write([]byte(pldConfigYAML))
	configSumHex := hex.EncodeToString(configSum.Sum(nil))
	return configSumHex,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				Labels:    r.getLabels(name),
			},
			StringData: map[string]string{
				"config.paladin.yaml": pldConfigYAML,
			},
		},
		nil
}

// generatePaladinConfig converts the Node CR spec to a Paladin JSON configuration
func (r *NodeReconciler) generatePaladinConfig(ctx context.Context, node *corev1alpha1.Node, namespace, name string) (string, error) {
	var pldConf pldconfig.PaladinConfig
	if node.Spec.Config != nil {
		err := yaml.Unmarshal([]byte(*node.Spec.Config), &pldConf)
		if err != nil {
			return "", fmt.Errorf("paladinConfigYAML is invalid: %s", err)
		}
	}
	if err := r.generatePaladinDBConfig(ctx, node, &pldConf, namespace, name); err != nil {
		return "", err
	}
	if err := r.generatePaladinSigners(ctx, node, &pldConf, namespace); err != nil {
		return "", err
	}
	sb := new(strings.Builder)
	_ = yaml.NewEncoder(sb).Encode(&pldConf)
	return sb.String(), nil
}

func (r *NodeReconciler) generatePaladinDBConfig(ctx context.Context, node *corev1alpha1.Node, pldConf *pldconfig.PaladinConfig, namespace, name string) error {
	dbSpec := &node.Spec.Database

	// If we're responsible for the runtime, we need to fill in the URI
	switch dbSpec.Mode {
	case corev1alpha1.DBMode_EmbeddedSQLite:
		pldConf.DB.Type = "sqlite"
		// We mix in our URI with whatever additional config has already been provided via YAML
		pldConf.DB.SQLite.SQLDBConfig.URI = "file:/db/db"
	case corev1alpha1.DBMode_SidecarPostgres:
		pldConf.DB.Type = "postgres"
		// Note password wrangling happens later
		if dbSpec.PasswordSecret == nil {
			defaultPasswordSecret := fmt.Sprintf("%s-db", name)
			dbSpec.PasswordSecret = &defaultPasswordSecret
		}
		if err := r.generateDBPasswordSecretIfNotExist(ctx, namespace, *dbSpec.PasswordSecret); err != nil {
			return err
		}
		pldConf.DB.Postgres.SQLDBConfig.URI = "postgres://localhost:5432/postgres?sslmode=disable"
	}

	// Get a handle to the DB config where we'll put password/migration info
	var sqlConfig *persistence.SQLDBConfig
	switch pldConf.DB.Type {
	case "sqlite":
		sqlConfig = &pldConf.DB.SQLite.SQLDBConfig
	case "postgres":
		sqlConfig = &pldConf.DB.Postgres.SQLDBConfig
	default:
		return fmt.Errorf("unsupported database type in configuration '%s'", pldConf.DB.Type)
	}

	// If we're responsible for loading the password for the Postgres URL, then load it from the secret
	if dbSpec.PasswordSecret != nil {
		dbUsername, dbPassword, err := r.retrieveUsernamePasswordSecret(ctx, node.Namespace, *dbSpec.PasswordSecret)
		if err != nil {
			return fmt.Errorf("failed to extract Postgres password secret '%s': %s", *dbSpec.PasswordSecret, err)
		}
		u, err := url.Parse(sqlConfig.URI)
		if err != nil {
			return fmt.Errorf("invalid Postgres URL '%s' to configure password: %s", sqlConfig.URI, err)
		}
		u.User = url.UserPassword(dbUsername, dbPassword)
		// Store back the updated URI
		sqlConfig.URI = u.String()
	}

	// If we're responsible for migration settings, then do it
	switch dbSpec.MigrationMode {
	case corev1alpha1.DBMigrationMode_Auto:
		truthy := true
		sqlConfig.AutoMigrate = &truthy
		sqlConfig.MigrationsDir = fmt.Sprintf("/app/db/migrations/%s", pldConf.DB.Type)
	}

	return nil
}

func (r *NodeReconciler) generateDBPasswordSecretIfNotExist(ctx context.Context, namespace, name string) error {
	secret := r.generateSecretTemplate(namespace, name)

	var foundSecret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, &foundSecret); err != nil && errors.IsNotFound(err) {
		secret.StringData = map[string]string{
			"username": "postgres",
			"password": randURLSafeBase64(32),
		}
		err = r.Create(ctx, secret)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}

func (r *NodeReconciler) generatePaladinSigners(ctx context.Context, node *corev1alpha1.Node, pldConf *pldconfig.PaladinConfig, namespace string) error {

	for i, s := range node.Spec.SecretBackedSigners {

		// Temporary restriction in Paladin
		if i > 0 {
			return fmt.Errorf("only one signer currently supported")
		}

		// TODO: This should resolve the keystore by "name" once we have the full key store config in Paladin
		pldSigner := &pldConf.Signer

		// Upsert a secret if we've been asked to. We use a mnemonic in this case (rather than directly generating a 32byte seed)
		if s.Type == corev1alpha1.SignerType_AutoHDWallet {
			pldSigner.KeyDerivation.Type = signerapi.KeyDerivationTypeBIP32
			pldSigner.KeyDerivation.SeedKeyPath = signerapi.ConfigKeyEntry{Name: "seed"}
			if err := r.generateBIP39SeedSecretIfNotExist(ctx, namespace, s.Secret); err != nil {
				return err
			}
		}

		// Note we update the fields we are responsible for, rather than creating the whole object
		// So detailed configuration can be provided in the config YAML
		pldSigner.KeyStore.Type = signerapi.KeyStoreTypeStatic
		pldSigner.KeyStore.Static.File = "/keystores/%s/keys.yaml"

	}

	return nil
}

func (r *NodeReconciler) generateBIP39SeedSecretIfNotExist(ctx context.Context, namespace, name string) error {
	secret := r.generateSecretTemplate(namespace, name)

	var foundSecret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, &foundSecret); err != nil && errors.IsNotFound(err) {
		var keyEntryJSON []byte
		var mnemonic string
		entropy, err := bip39.NewEntropy(256)
		if err == nil {
			mnemonic, err = bip39.NewMnemonic(entropy)
		}
		if err == nil {
			keyEntryJSON, err = json.MarshalIndent(map[string]signerapi.StaticKeyEntryConfig{
				"seed": {
					Encoding: "none",
					Inline:   mnemonic,
				},
			}, "", "  ")
		}
		if err != nil {
			return fmt.Errorf("failed to generate mnemonic: %s", err)
		}
		secret.StringData = map[string]string{
			"keys.yaml": string(keyEntryJSON),
		}
		err = r.Create(ctx, secret)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}

func (r *NodeReconciler) retrieveUsernamePasswordSecret(ctx context.Context, namespace, name string) (string, string, error) {
	var foundSecret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &foundSecret); err != nil {
		return "", "", err
	}
	return string(foundSecret.Data["username"]), string(foundSecret.Data["password"]), nil
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

func randURLSafeBase64(count int) string {
	bytes := make([]byte, count)
	_, _ = rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

// generateSecretTemplate generates a Secret for the Paladin configuration
func (r *NodeReconciler) generateSecretTemplate(namespace, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    r.getLabels(name),
		},
	}
}

func (r *NodeReconciler) getLabels(name string, extraLabels ...map[string]string) map[string]string {
	l := make(map[string]string, len(r.config.Paladin.Labels))
	l["app"] = generateName(name)

	for k, v := range r.config.Paladin.Labels {
		l[k] = v
	}
	for _, e := range extraLabels {
		for k, v := range e {
			l[k] = v
		}
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

func (r *NodeReconciler) deleteConfigSecret(ctx context.Context, namespace, name string) error {
	var foundSecret corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &foundSecret)
	if err == nil {
		return r.Delete(ctx, &foundSecret)
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
