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
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	corev1alpha1 "github.com/kaleido-io/paladin/operator/api/v1alpha1"
	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/rpcclient"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

// SmartContractDelpoymentReconciler reconciles a SmartContractDelpoyment object
type SmartContractDelpoymentReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=core.paladin.io,resources=smartcontractdeployents,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core.paladin.io,resources=smartcontractdeployents/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=core.paladin.io,resources=smartcontractdeployents/finalizers,verbs=update

func (r *SmartContractDelpoymentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// TODO: Add an admission webhook to make the bytecode and ABI immutable

	// Fetch the SmartContractDelpoyment instance
	var scd corev1alpha1.SmartContractDelpoyment
	if err := r.Get(ctx, req.NamespacedName, &scd); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get Paladin resource")
		return ctrl.Result{}, err
	}

	// If we don't have an idempotency key, then create one and re-reconcile
	if scd.Status.IdempotencyKey == "" {
		scd.Status.IdempotencyKey = fmt.Sprintf("k8s.%s.%d", scd.Name, scd.CreationTimestamp.UnixMilli())
		return r.updateStatusAndRequeue(ctx, &scd)
	}

	// Check availability of the Paladin node and deploy
	paladinRPC, err := r.getPaladinRPC(ctx, &scd)
	if err != nil {
		return ctrl.Result{}, err
	}
	if paladinRPC == "" {
		return ctrl.Result{RequeueAfter: 1 * time.Second}, nil
	}

	// If we don't have a transactionID to track, then submit
	if scd.Status.TransactionID == nil {
		return scd.submitTransactionAndRequeue(ctx, &scd, paladinRPC)
	}

	return ctrl.Result{}, nil
}

func (r *SmartContractDelpoymentReconciler) updateStatusAndRequeue(ctx context.Context, scd *corev1alpha1.SmartContractDelpoyment) (ctrl.Result, error) {
	if err := r.Status().Update(ctx, scd); err != nil {
		log.FromContext(ctx).Error(err, "Failed to update smart contract deployment status")
		return ctrl.Result{}, err
	}
	return ctrl.Result{Requeue: true}, nil // Run again immediately to submit
}

func (r *SmartContractDelpoymentReconciler) submitTransactionAndRequeue(ctx context.Context, scd *corev1alpha1.SmartContractDelpoyment, paladinRPC rpcclient.Client) (ctrl.Result, error) {

	var data tktypes.RawJSON
	if scd.Spec.ParamsJSON == "" {
		data = tktypes.RawJSON(scd.Spec.ParamsJSON)
	}
	var a abi.ABI

	var txn *ptxapi.Transaction
	err := paladinRPC.CallRPC(ctx, &txn, "ptx_sendTransaction", &ptxapi.TransactionInput{
		Transaction: ptxapi.Transaction{
			IdempotencyKey: scd.Status.IdempotencyKey,
			Type:           tktypes.Enum[ptxapi.TransactionType](scd.Spec.TxType),
			Domain:         scd.Spec.Domain,
			From:           scd.Spec.DeployKey,
			Data:           data,
		},
	})
	if err != nil {

	}

}

func (r *SmartContractDelpoymentReconciler) getPaladinURL(ctx context.Context, scd *corev1alpha1.SmartContractDelpoyment) (rpcclient.Client, error) {

	log := log.FromContext(ctx)
	var node corev1alpha1.Paladin
	if err := r.Get(ctx, types.NamespacedName{Name: scd.Spec.DeployNode, Namespace: scd.Namespace}, &node); err != nil {
		if errors.IsNotFound(err) {
			// short wait for node to become available
			log.Info(fmt.Sprintf("Waiting for paladin node '%s' to be created to deploy", scd.Spec.DeployNode))
			return nil, nil
		}
		// short wait for node to become available
		log.Info(fmt.Sprintf("Waiting for paladin node '%s' to become available to deploy", scd.Spec.DeployNode))
		return nil, nil
	}
	url := fmt.Sprintf("http://%s:8548", generatePaladinServiceHostname(scd.Spec.DeployNode, scd.Namespace))
	return rpcclient.NewHTTPClient(ctx, &pldconf.HTTPClientConfig{URL: url})

}

// SetupWithManager sets up the controller with the Manager.
func (r *SmartContractDelpoymentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha1.SmartContractDelpoyment{}).
		Complete(r)
}
