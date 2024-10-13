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
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/hyperledger/firefly-signer/pkg/abi"
	corev1alpha1 "github.com/kaleido-io/paladin/operator/api/v1alpha1"
	"github.com/kaleido-io/paladin/toolkit/pkg/algorithms"
	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/kaleido-io/paladin/toolkit/pkg/verifiers"
)

var registryABI = abi.ABI{
	// function registerIdentity(bytes32 parentIdentityHash, string memory name, address owner) public
	{
		Type: abi.Function,
		Name: "registerIdentity",
		Inputs: abi.ParameterArray{
			{Name: "parentIdentityHash", Type: "bytes32"},
			{Name: "name", Type: "string"},
			{Name: "owner", Type: "address"},
		},
	},
	// function setIdentityProperty(bytes32 identityHash, string memory name, string memory value) public
	{
		Type: abi.Function,
		Name: "setIdentityProperty",
		Inputs: abi.ParameterArray{
			{Name: "identityHash", Type: "bytes32"},
			{Name: "name", Type: "string"},
			{Name: "value", Type: "string"},
		},
	},
}

// PaladinRegistrationReconciler reconciles a PaladinRegistration object
type PaladinRegistrationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// allows generic functions by giving a mapping between the types and interfaces for the CR
var PaladinRegistrationCRMap = CRMap[corev1alpha1.PaladinRegistration, *corev1alpha1.PaladinRegistration, *corev1alpha1.PaladinRegistrationList]{
	NewList: func() *corev1alpha1.PaladinRegistrationList { return new(corev1alpha1.PaladinRegistrationList) },
	ItemsFor: func(list *corev1alpha1.PaladinRegistrationList) []corev1alpha1.PaladinRegistration {
		return list.Items
	},
	AsObject: func(item *corev1alpha1.PaladinRegistration) *corev1alpha1.PaladinRegistration { return item },
}

// +kubebuilder:rbac:groups=core.paladin.io,resources=paladinregistrations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core.paladin.io,resources=paladinregistrations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core.paladin.io,resources=paladinregistrations/finalizers,verbs=update

func (r *PaladinRegistrationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// TODO: Add an admission webhook to make the bytecode and ABI immutable

	// Fetch the PaladinRegistration instance
	var reg corev1alpha1.PaladinRegistration
	if err := r.Get(ctx, req.NamespacedName, &reg); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get PaladinRegistration resource")
		return ctrl.Result{}, err
	}

	// First reconcile until we've submitting the registration tx
	regTx := newTransactionReconcile(r.Client,
		"reg."+reg.Name,
		reg.Spec.RegistryAdminNode /* for the root entry */, reg.Namespace,
		&reg.Status.RegistrationTx,
		func() (bool, *ptxapi.TransactionInput, error) { return r.buildRegistrationTX(ctx, &reg) },
	)
	err := regTx.reconcile(ctx)
	if err != nil {
		return ctrl.Result{}, err
	} else if regTx.statusChanged {
		return r.updateStatusAndRequeue(ctx, &reg)
	} else if regTx.failed {
		return ctrl.Result{}, nil // don't go any further
	} else if !regTx.succeeded {
		return ctrl.Result{RequeueAfter: 1 * time.Second}, nil // we're waiting
	}

	// Now we need to run a TX for each transport (we'll check availability for each before we submit)
	for _, transportName := range reg.Spec.Transports {
		regTx := newTransactionReconcile(r.Client,
			"reg."+reg.Name+"."+transportName,
			reg.Spec.Node /* the node owns their transports */, reg.Namespace,
			&reg.Status.RegistrationTx,
			func() (bool, *ptxapi.TransactionInput, error) { return r.buildTransportTX(ctx, &reg, transportName) },
		)
		err := regTx.reconcile(ctx)
		if err != nil {
			return ctrl.Result{}, err
		} else if regTx.statusChanged {
			return r.updateStatusAndRequeue(ctx, &reg)
		} else if regTx.failed {
			return ctrl.Result{}, nil // don't go any further
		} else if !regTx.succeeded {
			return ctrl.Result{RequeueAfter: 1 * time.Second}, nil // we're waiting
		}
	}

	// Nothing left to do
	return ctrl.Result{}, nil
}

func (r *PaladinRegistrationReconciler) updateStatusAndRequeue(ctx context.Context, reg *corev1alpha1.PaladinRegistration) (ctrl.Result, error) {
	if err := r.Status().Update(ctx, reg); err != nil {
		log.FromContext(ctx).Error(err, "Failed to update Paladin registration status")
		return ctrl.Result{}, err
	}
	return ctrl.Result{Requeue: true}, nil // Run again immediately to submit
}

func (r *PaladinRegistrationReconciler) buildRegistrationTX(ctx context.Context, reg *corev1alpha1.PaladinRegistration) (bool, *ptxapi.TransactionInput, error) {

	// We ask the node its name, so we know what to register it as
	regNodeRPC, err := getPaladinRPC(ctx, r.Client, reg.Spec.Node, reg.Namespace)
	if err != nil || regNodeRPC == nil {
		return false, nil, err // not ready, or error
	}
	var nodeName string
	if err := regNodeRPC.CallRPC(ctx, &nodeName, "transport_nodeName"); err != nil || nodeName == "" {
		return false, nil, err
	}

	// We also ask it to resolve its key down to an address
	var nodeOwnerAddress string
	if err := regNodeRPC.CallRPC(ctx, &nodeName, "ptx_resolveLocalVerifier",
		reg.Spec.NodeKey, algorithms.ECDSA_SECP256K1, verifiers.ETH_ADDRESS,
	); err != nil || nodeOwnerAddress == "" {
		return false, nil, err
	}

	registration := map[string]any{
		"parentIdentityHash": tktypes.Bytes32{}, // zero for root
		"name":               nodeName,
		"owner":              nodeOwnerAddress,
	}

	return true, &ptxapi.TransactionInput{
		Transaction: ptxapi.Transaction{
			Type:     ptxapi.TransactionTypePublic.Enum(),
			Function: registryABI.Functions()["registerIdentity"].String(),
			From:     reg.Spec.RegistryAdminKey, // registry admin registers the root entry for the node
			Data:     tktypes.JSONString(registration),
		},
		ABI: registryABI,
	}, nil
}

func (r *PaladinRegistrationReconciler) buildTransportTX(ctx context.Context, reg *corev1alpha1.PaladinRegistration, transportName string) (bool, *ptxapi.TransactionInput, error) {

	// Get the details from the node
	regNodeRPC, err := getPaladinRPC(ctx, r.Client, reg.Spec.Node, reg.Namespace)
	if err != nil || regNodeRPC == nil {
		return false, nil, err // not ready, or error
	}
	var transportDetails string
	if err := regNodeRPC.CallRPC(ctx, &transportDetails, "transport_localTransportDetails", transportName); err != nil || transportDetails == "" {
		return false, nil, err
	}

	// We also wait until this node has indexed the registration of the root node,
	// and use that to extract the hash

	property := map[string]any{
		"identityHash": nodeEntryHash.String(),
		"name":         fmt.Sprintf("transport.%s", transportName),
		"value":        transportDetails,
	}

	return true, &ptxapi.TransactionInput{
		Transaction: ptxapi.Transaction{
			Type:     ptxapi.TransactionTypePublic.Enum(),
			Function: registryABI.Functions()["setIdentityProperty"].String(),
			From:     reg.Spec.RegistryAdminKey, // registry admin registers the root entry for the node
			Data:     tktypes.JSONString(registration),
		},
		ABI: registryABI,
	}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PaladinRegistrationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha1.PaladinRegistration{}).
		Complete(r)
}
