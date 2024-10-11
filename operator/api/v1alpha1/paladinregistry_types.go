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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type RegistryType string

const (
	RegistryTypeEVM RegistryType = "evm"
)

// PaladinRegistrySpec defines the desired state of PaladinRegistry
type PaladinRegistrySpec struct {
	// +kubebuilder:validation:Enum=evm
	// +kubebuilder:default=evm
	Type RegistryType `json:"type"`
	// Config specific to EVM based registry
	EVM EVMRegistryConfig `json:"evm,omitempty"`
	// JSON configuration specific to the individual registry
	ConfigJSON string `json:"configJSON"`
}

type EVMRegistryConfig struct {
	// Reference to a SmartContractDeployment CR that is used to deploy the registry
	SmartContractDeployment string `json:"smartContractDeployment,omitempty"`
	// If you have separately deployed the registry, supply the registry address directly
	ContractAddress string `json:"contractAddress,omitempty"`
}

type RegistryStatus string

const (
	RegistryStatusPending   RegistryStatus = "Pending"
	RegistryStatusAvailable RegistryStatus = "Available"
)

// PaladinRegistryStatus defines the observed state of PaladinRegistry
type PaladinRegistryStatus struct {
	Status          RegistryStatus `json:"status"`
	ContractAddress string         `json:"contractAddress,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
//+kubebuilder:resource:shortName="reg"
//+kubebuilder:printcolumn:name="Type",type="string",JSONPath=`.spec.type`
//+kubebuilder:printcolumn:name="Status",type="string",JSONPath=`.status.status`
//+kubebuilder:printcolumn:name="Contract",type="string",JSONPath=`.status.contractAddress`

// PaladinRegistry is the Schema for the paladinregistries API
type PaladinRegistry struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PaladinRegistrySpec   `json:"spec,omitempty"`
	Status PaladinRegistryStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PaladinRegistryList contains a list of PaladinRegistry
type PaladinRegistryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PaladinRegistry `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PaladinRegistry{}, &PaladinRegistryList{})
}
