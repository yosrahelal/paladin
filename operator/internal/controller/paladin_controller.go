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

	pldconfig "github.com/kaleido-io/paladin/core/pkg/config"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/core/pkg/signer/signerapi"
	"github.com/tyler-smith/go-bip39"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/yaml"

	corev1alpha1 "github.com/kaleido-io/paladin/operator/api/v1alpha1"
	"github.com/kaleido-io/paladin/operator/pkg/config"
)

// PaladinReconciler reconciles a Paladin object
type PaladinReconciler struct {
	client.Client
	config *config.Config
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=core.paladin.io,resources=paladins,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core.paladin.io,resources=paladins/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=core.paladin.io,resources=paladins/finalizers,verbs=update

// Reconcile implements the logic when a Paladin resource is created, updated, or deleted
func (r *PaladinReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Generate a name for the Paladin resources
	name := generatePaladinName(req.Name)
	namespace := req.Namespace

	// Fetch the Paladin instance
	var node corev1alpha1.Paladin
	if err := r.Get(ctx, req.NamespacedName, &node); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Paladin resource deleted, deleting related resources")
			r.deleteService(ctx, namespace, name)
			r.deleteStatefulSet(ctx, namespace, name)
			r.deleteConfigSecret(ctx, namespace, name)

			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get Paladin resource")
		return ctrl.Result{}, err
	}

	configSum, _, err := r.createConfigMap(ctx, &node, name)
	if err != nil {
		log.Error(err, "Failed to create Paladin config map")
		return ctrl.Result{}, err
	}
	log.Info("Created Paladin config map", "Name", name)

	if _, err := r.createService(ctx, &node, name); err != nil {
		log.Error(err, "Failed to create Paladin Service")
		return ctrl.Result{}, err
	}
	log.Info("Created Paladin Service", "Name", name)

	if _, err := r.createPDB(ctx, &node, name); err != nil {
		log.Error(err, "Failed to create Paladin pod disruption budget")
		return ctrl.Result{}, err
	}
	log.Info("Created Paladin pod disruption budget", "Name", name)

	ss, err := r.createStatefulSet(ctx, &node, name, configSum)
	if err != nil {
		log.Error(err, "Failed to create Paladin StatefulSet")
		return ctrl.Result{}, err
	}
	log.Info("Created Paladin StatefulSet", "Name", ss.Name, "Namespace", ss.Namespace)

	// TODO: Update the Paladin status
	// node.Status.Name = ss.GetName()
	// node.Status.Namespace = ss.GetNamespace()
	// if err := r.Status().Update(ctx, &node); err != nil {
	// 	log.Error(err, "Failed to update Paladin status")
	// 	return ctrl.Result{}, err
	// }

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PaladinReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Load the controller configuration
	config, err := config.LoadConfig() // Load the config from file
	if err != nil {
		return err
	}
	r.config = config

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha1.Paladin{}).
		Complete(r)
}

func (r *PaladinReconciler) createStatefulSet(ctx context.Context, node *corev1alpha1.Paladin, name, configSum string) (*appsv1.StatefulSet, error) {
	statefulSet := r.generateStatefulSetTemplate(node, name, configSum)

	if node.Spec.Database.Mode == corev1alpha1.DBMode_SidecarPostgres {
		// Earlier processing responsible for ensuring this is non-nil
		r.addPostgresSidecar(statefulSet, *node.Spec.Database.PasswordSecret)
		if err := r.createPostgresPVC(ctx, node, name); err != nil {
			return nil, err
		}
	}

	// Used by Postgres sidecar, but also custom DB creation - a DB secret needs wiring up to env vars for DSNParams
	if node.Spec.Database.PasswordSecret != nil {
		if err := r.addPaladinDBSecret(ctx, statefulSet, *node.Spec.Database.PasswordSecret); err != nil {
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
		foundStatefulSet.Spec.Template.Annotations = statefulSet.Spec.Template.Annotations
		foundStatefulSet.Spec.Template.Labels = statefulSet.Spec.Template.Labels
		// TODO: Other things that can be merged?
		return &foundStatefulSet, r.Update(ctx, &foundStatefulSet)
	}
	return statefulSet, nil

}

func (r *PaladinReconciler) withStandardAnnotations(annotations map[string]string) map[string]string {
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

func (r *PaladinReconciler) generatePDBTemplate(node *corev1alpha1.Paladin, name string) *policyv1.PodDisruptionBudget {
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

func (r *PaladinReconciler) createPDB(ctx context.Context, node *corev1alpha1.Paladin, name string) (*policyv1.PodDisruptionBudget, error) {
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

func (r *PaladinReconciler) generateStatefulSetTemplate(node *corev1alpha1.Paladin, name, configSum string) *appsv1.StatefulSet {
	// Define the StatefulSet to run Paladin using the ConfigMap
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: node.Namespace,
			Annotations: r.withStandardAnnotations(map[string]string{
				"kubectl.kubernetes.io/default-container": "paladin",
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
									Name:          "rpc-http",
									ContainerPort: 8548,
									Protocol:      corev1.ProtocolTCP,
								},
								{
									Name:          "rpc-ws",
									ContainerPort: 8549,
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

func (r *PaladinReconciler) addPostgresSidecar(ss *appsv1.StatefulSet, passwordSecret string) {
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

func (r *PaladinReconciler) createPostgresPVC(ctx context.Context, node *corev1alpha1.Paladin, name string) error {
	pvc := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-pgdata", name),
			Namespace: node.Namespace,
			Labels:    r.getLabels(node),
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

func (r *PaladinReconciler) addKeystoreSecretMounts(ss *appsv1.StatefulSet, signers []corev1alpha1.SecretBackedSigner) {
	paladinContainer := &ss.Spec.Template.Spec.Containers[0]
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

func (r *PaladinReconciler) addPaladinDBSecret(ctx context.Context, ss *appsv1.StatefulSet, secretName string) error {
	_, _, err := r.retrieveUsernamePasswordSecret(ctx, ss.Namespace, secretName)
	if err != nil {
		return fmt.Errorf("failed to extract username/password from DB password secret '%s': %s", secretName, err)
	}

	paladinContainer := &ss.Spec.Template.Spec.Containers[0]
	paladinContainer.VolumeMounts = append(paladinContainer.VolumeMounts, corev1.VolumeMount{
		Name:      "db-creds",
		MountPath: "/db-creds",
	})
	ss.Spec.Template.Spec.Volumes = append(ss.Spec.Template.Spec.Volumes, corev1.Volume{
		Name: "db-creds",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: secretName,
			},
		},
	})
	return nil
}

func (r *PaladinReconciler) createConfigMap(ctx context.Context, node *corev1alpha1.Paladin, name string) (string, *corev1.ConfigMap, error) {
	configSum, configMap, err := r.generateConfigMap(ctx, node, name)
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

// generatePaladinConfigMapTemplate generates a ConfigMap for the Paladin configuration
func (r *PaladinReconciler) generateConfigMap(ctx context.Context, node *corev1alpha1.Paladin, name string) (string, *corev1.ConfigMap, error) {
	pldConfigYAML, err := r.generatePaladinConfig(ctx, node, name)
	if err != nil {
		return "", nil, err
	}
	configSum := md5.New()
	configSum.Write([]byte(pldConfigYAML))
	configSumHex := hex.EncodeToString(configSum.Sum(nil))
	return configSumHex,
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: node.Namespace,
				Labels:    r.getLabels(node),
			},
			Data: map[string]string{
				"config.paladin.yaml": pldConfigYAML,
			},
		},
		nil
}

// generatePaladinConfig converts the Paladin CR spec to a Paladin YAML configuration
func (r *PaladinReconciler) generatePaladinConfig(ctx context.Context, node *corev1alpha1.Paladin, name string) (string, error) {
	var pldConf pldconfig.PaladinConfig
	if node.Spec.Config != nil {
		err := yaml.Unmarshal([]byte(*node.Spec.Config), &pldConf)
		if err != nil {
			return "", fmt.Errorf("paladinConfigYAML is invalid: %s", err)
		}
	}

	// Node name can be overridden, but defaults to the CR name
	if pldConf.NodeName == "" {
		pldConf.NodeName = node.Name
	}

	// Merge in the ports for our networking config (which we need to match our service defs)
	pldConf.RPCServer.HTTP.Port = ptrTo(8548)
	pldConf.RPCServer.WS.Port = ptrTo(8549)

	// DB needs merging from user config and our config
	if err := r.generatePaladinDBConfig(ctx, node, &pldConf, name); err != nil {
		return "", err
	}

	// Signer config needs merging
	if err := r.generatePaladinSigners(ctx, node, &pldConf); err != nil {
		return "", err
	}

	// Bind to the a local besu node if we've been configured with one
	if node.Spec.BesuNode != "" {
		pldConf.Blockchain.HTTP.URL = fmt.Sprintf("http://%s:8545", generateBesuServiceHostname(node.Spec.BesuNode, node.Namespace))
		pldConf.Blockchain.WS.URL = fmt.Sprintf("ws://%s:8546", generateBesuServiceHostname(node.Spec.BesuNode, node.Namespace))
	}
	b, _ := yaml.Marshal(&pldConf)
	return string(b), nil
}

func (r *PaladinReconciler) generatePaladinDBConfig(ctx context.Context, node *corev1alpha1.Paladin, pldConf *pldconfig.PaladinConfig, name string) error {
	dbSpec := &node.Spec.Database

	// If we're responsible for the runtime, we need to fill in the URI
	switch dbSpec.Mode {
	case corev1alpha1.DBMode_EmbeddedSQLite:
		pldConf.DB.Type = "sqlite"
		// We mix in our URI with whatever additional config has already been provided via YAML
		pldConf.DB.SQLite.SQLDBConfig.DSN = "file:/db/db"
	case corev1alpha1.DBMode_SidecarPostgres:
		pldConf.DB.Type = "postgres"
		// Note password wrangling happens later
		if dbSpec.PasswordSecret == nil {
			defaultPasswordSecret := fmt.Sprintf("%s-db", name)
			dbSpec.PasswordSecret = &defaultPasswordSecret
		}
		if err := r.generateDBPasswordSecretIfNotExist(ctx, node, *dbSpec.PasswordSecret); err != nil {
			return err
		}
		pldConf.DB.Postgres.SQLDBConfig.DSN = "postgres://{{.username}}:{{.password}}@localhost:5432/postgres?sslmode=disable"
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
		if pldConf.DB.Postgres.SQLDBConfig.DSNParams == nil {
			pldConf.DB.Postgres.SQLDBConfig.DSNParams = map[string]persistence.DSNParamLocation{}
		}
		pldConf.DB.Postgres.SQLDBConfig.DSNParams["username"] = persistence.DSNParamLocation{File: "/db-creds/username"}
		pldConf.DB.Postgres.SQLDBConfig.DSNParams["password"] = persistence.DSNParamLocation{File: "/db-creds/password"}
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

func (r *PaladinReconciler) generateDBPasswordSecretIfNotExist(ctx context.Context, node *corev1alpha1.Paladin, name string) error {
	secret := r.generateSecretTemplate(node, name)

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

func (r *PaladinReconciler) generatePaladinSigners(ctx context.Context, node *corev1alpha1.Paladin, pldConf *pldconfig.PaladinConfig) error {

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
			if err := r.generateBIP39SeedSecretIfNotExist(ctx, node, s.Secret); err != nil {
				return err
			}
		}

		// Note we update the fields we are responsible for, rather than creating the whole object
		// So detailed configuration can be provided in the config YAML
		pldSigner.KeyStore.Type = signerapi.KeyStoreTypeStatic
		pldSigner.KeyStore.Static.File = fmt.Sprintf("/keystores/%s/keys.yaml", s.Name)

	}

	return nil
}

func (r *PaladinReconciler) generateBIP39SeedSecretIfNotExist(ctx context.Context, node *corev1alpha1.Paladin, name string) error {
	secret := r.generateSecretTemplate(node, name)

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

func (r *PaladinReconciler) retrieveUsernamePasswordSecret(ctx context.Context, namespace, name string) (string, string, error) {
	var foundSecret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &foundSecret); err != nil {
		return "", "", err
	}
	return string(foundSecret.Data["username"]), string(foundSecret.Data["password"]), nil
}

func (r *PaladinReconciler) createService(ctx context.Context, node *corev1alpha1.Paladin, name string) (*corev1.Service, error) {
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

// generateServiceTemplate generates a ConfigMap for the Paladin configuration
func (r *PaladinReconciler) generateServiceTemplate(node *corev1alpha1.Paladin, name string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: node.Namespace,
			Labels:    r.getLabels(node),
		},
		Spec: corev1.ServiceSpec{
			Selector: r.getLabels(node),
			// TODO: Complete the ServiceSpec (e.g., ports, type, etc.)
			// It will most likely get generated from the config
			Ports: []corev1.ServicePort{
				{
					Name:       "rpc-http",
					Port:       8548,
					TargetPort: intstr.FromInt(8548),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       "rpc-ws",
					Port:       8549,
					TargetPort: intstr.FromInt(8549),
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
func (r *PaladinReconciler) generateSecretTemplate(node *corev1alpha1.Paladin, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: node.Namespace,
			Labels:    r.getLabels(node),
		},
	}
}

func (r *PaladinReconciler) getLabels(node *corev1alpha1.Paladin, extraLabels ...map[string]string) map[string]string {
	l := make(map[string]string, len(r.config.Paladin.Labels))
	l["app"] = generatePaladinName(node.Name)

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

// generatePaladinName generates a name for the Paladin resources based on the Paladin name.
// this is for generating unique names for the resources
func generatePaladinName(n string) string {
	return fmt.Sprintf("paladin-%s", n)
}

func (r *PaladinReconciler) deleteStatefulSet(ctx context.Context, namespace, name string) error {
	var foundStatefulSet appsv1.StatefulSet
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &foundStatefulSet)
	if err == nil {
		return r.Delete(ctx, &foundStatefulSet)
	}
	return nil

}

func (r *PaladinReconciler) deleteConfigSecret(ctx context.Context, namespace, name string) error {
	var foundSecret corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &foundSecret)
	if err == nil {
		return r.Delete(ctx, &foundSecret)
	}
	return err
}

func (r *PaladinReconciler) deleteService(ctx context.Context, namespace, name string) error {

	var foundSvc corev1.Service
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &foundSvc)
	if err == nil {
		return r.Delete(ctx, &foundSvc)
	}
	return err
}
