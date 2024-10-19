# Installation

## Install 

Run the helm install command
```
helm install paladin ... -n paladin --create-namespace
```

This will:

1. Install CRD chart
2. Install cert-manager chart
3. Install paladin-operator chart


## Create blockchain network

```
kubectl apply -f https://github/<path to CR - besu>
kubectl apply -f https://github/<path to CR - genasis>
kubectl apply -f https://github/<path to CR - paladin>
```

## Deploy smart contracts

```
kubectl apply -f https://github/<path to CR - noto>
kubectl apply -f https://github/<path to CR - zeto>
kubectl apply -f https://github/<path to CR - pente>
```

## Create private transaction

```
kubectl apply -f https://github/<path to CR - transaction>
```

### Proof of privacy

#### UI

Open paladin UI in browser - http://127.0.0.1:1234/ui

1. Navigate to node1 view. Transaction is visible in node1
2. Navigate to node2 view. Transaction is visible in node2
3. Navigate to node3 view. Transaction is not visible in node3  

#### Command line

1. View node1 transaction: `curl GET <>` > the transaction is visible
1. View node2 transaction: `curl GET <>` > the transaction is visible
1. View node3 transaction: `curl GET <>` > the transaction is NOT visible/encrypted