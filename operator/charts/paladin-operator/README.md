# Paladin Operator Helm Chart

This chart is part of the larger Paladin ecosystem. For comprehensive setup and usage instructions, please refer to the [main Paladin documentation](https://lf-decentralized-trust-labs.github.io/paladin/head/getting-started/installation/).

## Node Configuration

The chart supports flexible node configuration with three parameters:

### Standard Mode (Default)
By default, the chart deploys an equal number of Paladin and Besu nodes using the `nodeCount` parameter:

```yaml
nodeCount: 3  # Deploys 3 Paladin nodes + 3 Besu nodes
```

### Single Besu Mode (Resource Optimized)
For resource-constrained environments (like GitHub Actions), you can use the `paladinNodeCount` parameter to deploy multiple Paladin nodes with a single Besu node:

```yaml
paladinNodeCount: 5  # Deploys 5 Paladin nodes + 1 Besu node
```

**When `paladinNodeCount` is set, `besuNodeCount` automatically becomes 1.**

### Node Connectivity Logic
- **Single Besu node**: All Paladin nodes connect to the first Besu node (`node1`)
- **Multiple Besu nodes**: Each Paladin node connects to its corresponding Besu node (1:1 mapping)

This configuration is particularly useful for:
- Testing scenarios where you need multiple Paladin nodes
- CI/CD environments with limited resources
- Development environments where you want to test Paladin network behavior without the overhead of multiple Besu instances

## Auto-Generated CRs

**Important**: Some of the CRs deployed by this chart are **auto-generated during the chart release process** and therefore cannot be found in the `templates/` directory of this repository.

### Generation Process

The chart uses an automated build process to generate smart contract-related CRs:

1. **Smart Contract Processing**: The [`../../contractpkg/main.go`](../../contractpkg/main.go) program processes compiled smart contract artifacts and generates corresponding Kubernetes CRs.

2. **Template Generation**: During the build process (see [`../../Makefile`](../../Makefile)), the tool:
   - Reads smart contract build artifacts
   - Generates `SmartContractDeployment` CRs
   - Creates `PaladinDomain` and `PaladinRegistry` CRs
   - Applies appropriate templating for different installation modes
   - Packages everything into the final Helm chart

3. **Build Integration**: The Makefile targets like `prepare-crd-chart` and `helm-install-dependencies` orchestrate this generation process.

