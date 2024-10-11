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
	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SmartContractDelpoymentSpec defines the desired state of SmartContractDelpoyment
type SmartContractDelpoymentSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +kubebuilder:validation:Enum=public;private
	// Type of transaction to submit to Paladin
	TxType string `json:"txType"`
	// The ABI of the smart contract - provides the constructor parameter definition
	ABI string `json:"abi"`
	// The bytecode of the smart contract
	Bytecode string `json:"bytecode"`
	// The node to use to deploy - reference to a PaladinNode CR
	DeployNode string `json:"deployNode"`
	// Reference to the signing key to use to deploy
	DeployKey string `json:"deployKey"`
	// Domain for private transactions
	Domain string `json:"domain"`
	// JSON parameter data
	ParamsJSON string `json:"paramsJSON"`
}

type TransactionStatus string

const (
	TransactionStatusPending  TransactionStatus = "Pending"
	TransactionStatusSuccess  TransactionStatus = "Success"
	TransactionStatusFailed   TransactionStatus = "Failed"
	TransactionStatusRejected TransactionStatus = "Rejected"
)

// SmartContractDelpoymentStatus defines the observed state of SmartContractDelpoyment
type SmartContractDelpoymentStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	TransactionStatus TransactionStatus `json:"transactionStatus,omitempty"`

	IdempotencyKey string     `json:"idempotencyKey,omitempty"`
	TransactionID  *uuid.UUID `json:"transactionID,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:shortName="scd"

// SmartContractDelpoyment is the Schema for the smartcontractdeployents API
type SmartContractDelpoyment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SmartContractDelpoymentSpec   `json:"spec,omitempty"`
	Status SmartContractDelpoymentStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// SmartContractDelpoymentList contains a list of SmartContractDelpoyment
type SmartContractDelpoymentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SmartContractDelpoyment `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SmartContractDelpoyment{}, &SmartContractDelpoymentList{})
}
