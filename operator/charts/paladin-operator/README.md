# Paladin Operator Helm Chart

This chart is part of the larger Paladin ecosystem. For comprehensive setup and usage instructions, please refer to the [main Paladin documentation](https://lf-decentralized-trust-labs.github.io/paladin/head/getting-started/installation/).

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

