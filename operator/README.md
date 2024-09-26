# Paladin-Operator

## Description

The Paladin Operator is a Kubernetes operator designed to manage Paladin nodes. It provides functionality to deploy, configure, and manage Paladin instances within a Kubernetes cluster.

## Getting Started

### Prerequisites

- **Go** version v1.21.0+
- **Docker** version 17.03+.
- **kubectl** version v1.11.3+.
- Access to a **Kubernetes** cluster version v1.11.3+.

### Running the Operator Locally

You can run the Paladin operator on your local machine for development or testing purposes.

#### Prerequisites

1. Create a Kubernetes cluster using Kind (or any other tool):
   ```sh
   kind create cluster --name <context-name>
   ```

2. Build the Paladin operator image locally:
   ```sh
   docker build -t paladin:<tag> .
   ```

3. Load the image into the Kind cluster:
   ```sh
   kind load docker-image paladin:<tag> --name <context-name>
   ```

4. Update the configuration in `config/config.json` to match your setup.

#### Running the Operator

To run the operator locally:

```sh
make run
```

#### Creating an Instance

After the operator is running, you can create a Paladin instance:

```sh
make create-instance
```

### Running the Operator in a Cluster

To deploy the Paladin operator inside a Kubernetes cluster:

#### Prerequisites

1. Create a Kubernetes cluster using Kind (or any other tool):
   ```sh
   kind create cluster --name <context-name>
   ```

2. Build the Paladin operator image locally:
   ```sh
   docker build -t paladin:<tag> .
   ```

3. Load the image into the cluster:
   ```sh
   kind load docker-image paladin:<tag> --name <context-name>
   ```

4. Update the Helm chart values file:
   Edit `deploy/paladin-operator/values.yaml` under `operator.configMap.data` to include the necessary configuration for your deployment. *(Note: This process may need improvement for user-friendliness.)*

#### Building and Loading the Image

To build the operator image and load it into the cluster:

```sh
make docker-load CLUSTER_NAME=<cluster-name>
```

#### Installing the Helm Chart

Install the operator using Helm:

```sh
make install
```

#### Creating an Instance

Once the operator is deployed, you can create a Paladin instance by running:

```sh
make create-instance
```

### Cleanup

To remove the operator and clean up resources:

```sh
make clean
```

## Development

This project was scaffolded using the **operator-sdk**.

To add a new resource or controller, use the following command:

```sh
operator-sdk create api
```

After creating the resource, update the code in the `api/` directory by defining the necessary structures and specifications.

To ensure your changes are valid, run:

```sh
make build
```

Once the structures are defined, update the **Reconcile** function in the `internal/controller` package to implement the business logic for the resource.
