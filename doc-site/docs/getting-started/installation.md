# Installation Guide

## Installation

### Prerequisites
* Access to a running Kubernetes cluster (e.g. kind, minikube, ecr, etc.)
* Helm installed
* Kubectl installed

### Step 1: Install the CRD Chart
Install the CRD chart that contains the necessary Custom Resource Definitions (CRDs) for the Paladin operator:
```bash
helm repo add paladin https://LF-Decentralized-Trust-labs.github.io/paladin --force-update
helm upgrade --install paladin-crds paladin/paladin-operator-crd
```

### Step 2: Install cert-manager CRDs
[Install the cert-manager CRDs](https://artifacthub.io/packages/helm/cert-manager/cert-manager):
```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.16.1/cert-manager.crds.yaml
helm repo add jetstack https://charts.jetstack.io --force-update
helm install cert-manager --namespace cert-manager --version v1.16.1 jetstack/cert-manager --create-namespace
```

### Step 3: Install the Paladin Operator Chart
Install the Paladin operator chart:
```bash
helm upgrade --install paladin paladin/paladin-operator -n paladin --create-namespace \
    --set paladin.namespace=paladin \
    --set cert-manager.enabled=false
```

### Outcome

This process will:

1. Install the cert-manager chart.
2. Install the paladin-operator chart.
3. Create a Besu network with 3 nodes.
4. Create a Paladin network with 3 nodes, each associated with one of the Besu nodes.
5. Deploy smart contracts to the blockchain.

## Accessing the UI

To open the Paladin UI in your browser, go to:
```
http://<cluster IP>:<paladin service port>/ui
```

## Uninstall

To remove the Paladin operator and related resources, run the following commands:
```bash
helm uninstall paladin -n paladin
helm uninstall paladin-crds
kubectl delete namespace paladin
helm uninstall cert-manager -n cert-manager
kubectl delete -f https://github.com/cert-manager/cert-manager/releases/download/v1.16.1/cert-manager.crds.yaml
kubectl delete namespace cert-manager
```