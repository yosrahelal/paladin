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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// NodeSpec defines the desired state of Node
type NodeSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Settings from this config will be loaded as YAML and used as the base of the configuration.
	Config *string `json:"config,omitempty"`
	// Database settings allow operator governed convenience functions for setting up the database
	// with auto-generation/auto-edit of the DB related config sections
	Database *Database `json:"database,omitempty"`
}

const DBMode_EmbeddedSQLite = "embeddedSQLite"
const DBMode_SidecarPostgres = "sidecarPostgres"
const DBMigrationMode_Auto = "auto"

// Database configuration
type Database struct {
	// +kubebuilder:validation:Enum=preConfigured;sidecarPostgres;embeddedSQLite
	// +kubebuilder:default=preConfigured
	Mode string `json:"mode,omitempty"`
	// +kubebuilder:validation:Enum=preConfigured;auto
	// +kubebuilder:default=preConfigured
	MigrationMode string `json:"migrationMode,omitempty"`
	// If set the URI in the config will be updated with the password in this secret.
	// For sidecarPostgres a default password will be generated and stored for you, and this setting only modifies the secret name
	PasswordSecret *string                           `json:"postgresPasswordSecret,omitempty"`
	PVCTemplate    *corev1.PersistentVolumeClaimSpec `json:"pvcTemplate,omitempty"`
}

/*
// Config is the top-level configuration for the node
type Config struct {
    NodeName  string   `json:"nodeName,omitempty"`
    DB        Database `json:"db,omitempty"`
    GRPC      GRPCConfig `json:"grpc,omitempty"`
    RPCServer RPCServerConfig `json:"rpcServer,omitempty"`
    Blockchain BlockchainConfig `json:"blockchain,omitempty"`
    Signer    SignerConfig `json:"signer,omitempty"`
}

type NodeStatus struct {
    State   string `json:"state,omitempty"`   // Pending, Running, Failed
    Ready   bool   `json:"ready,omitempty"`
    Message string `json:"message,omitempty"` // Detailed status or error message
}

type SQLiteConfig struct {
    URI           string `json:"uri,omitempty"`
    AutoMigrate   bool   `json:"autoMigrate,omitempty"`
    MigrationsDir string `json:"migrationsDir,omitempty"`
    DebugQueries  bool   `json:"debugQueries,omitempty"`
}

type PostgresConfig struct {
    URI           string `json:"uri,omitempty"`
    AutoMigrate   bool   `json:"autoMigrate,omitempty"`
    MigrationsDir string `json:"migrationsDir,omitempty"`
    DebugQueries  bool   `json:"debugQueries,omitempty"`
}

// GRPC configuration
type GRPCConfig struct {
    ShutdownTimeout int `json:"shutdownTimeout,omitempty"`
}

// RPC Server configuration
type RPCServerConfig struct {
    HTTP HTTPServerConfig `json:"http,omitempty"`
    WS   WSServerConfig   `json:"ws,omitempty"`
}

type HTTPServerConfig struct {
    Port            int `json:"port,omitempty"`
    ShutdownTimeout int `json:"shutdownTimeout,omitempty"`
}

type WSServerConfig struct {
    Disabled        bool `json:"disabled,omitempty"`
    ShutdownTimeout int `json:"shutdownTimeout,omitempty"`
}

// Blockchain configuration
type BlockchainConfig struct {
    HTTP BlockchainHTTPConfig `json:"http,omitempty"`
    WS   BlockchainWSConfig   `json:"ws,omitempty"`
}

type BlockchainHTTPConfig struct {
    URL string `json:"url,omitempty"`
}

type BlockchainWSConfig struct {
    URL                   string `json:"url,omitempty"`
    InitialConnectAttempts int    `json:"initialConnectAttempts,omitempty"`
}

// Signer configuration
type SignerConfig struct {
    KeyDerivation KeyDerivationConfig `json:"keyDerivation,omitempty"`
    KeyStore      KeyStoreConfig      `json:"keyStore,omitempty"`
}

type KeyDerivationConfig struct {
    Type string `json:"type,omitempty"`
}

type KeyStoreConfig struct {
    Type   string         `json:"type,omitempty"`
    Static StaticKeyStore `json:"static,omitempty"`
}

type StaticKeyStore struct {
    Keys StaticKeys `json:"keys,omitempty"`
}

type StaticKeys struct {
    Seed SeedConfig `json:"seed,omitempty"`
}

type SeedConfig struct {
    Encoding string `json:"encoding,omitempty"`
    Inline   string `json:"inline,omitempty"`
}
*/

// StatusReason is an enumeration of possible failure causes.  Each StatusReason
// must map to a single HTTP status code, but multiple reasons may map
// to the same HTTP status code.
// TODO: move to apiserver
type StatusReason string

// NodeStatus defines the observed state of Node
type NodeStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster

	// TODO: What fields should be here?
	// Here are some ideas, but this means the operator will have to track the state of the pod as well (which is not ideal)
	// IP        string `json:"ip,omitempty"`
	// Name      string `json:"name,omitempty"`
	// Namespace string `json:"namespace,omitempty"`

	// Important: Run "make" to regenerate code after modifying this file
	Status string `json:"Status,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Node is the Schema for the nodes API
type Node struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NodeSpec   `json:"spec,omitempty"`
	Status NodeStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// NodeList contains a list of Node
type NodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Node `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Node{}, &NodeList{})
}
