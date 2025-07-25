# Workflow Overview

This repository is equipped with automated workflows that streamline key processes for PRs, changes to the `main` branch, and releases. These workflows ensure smooth development, testing, and deployment cycles.

## PR Opened 🚦
When a developer opens a PR, several automated checks are triggered to validate the changes:

- **[Build (PR)](workflows/on-pr.yaml):**  
  Runs essential tasks to ensure code quality and reliability:
  - **Build and Test:** Compiles the code and runs tests for all subdirectories using [build.yaml](workflows/build.yaml).
  - **[Build Docker Images](workflows/build-image.yaml):** Builds Docker images based on PR changes for local validation.  
    > **Note:** These images are **not published** to a registry.
  - **[Template the Helm Chart](workflows/build-chart.yaml):** Rebuilds and validates Helm charts for correctness.  
    > **Note:** Charts are **not published** but tested locally.

- **[Test Tutorials](workflows/on-pr-push-tutorials.yaml):**  
  Ensures examples remain functional with the latest SDK:
  - **Backwards Compatibility:** Tests with published SDK and ABI versions
  - **Forward Compatibility:** Tests with locally built SDK and ABI
  - **Commands:** Runs both `start` and `verify` commands for comprehensive testing
  - **Purpose:** Validates that tutorial changes don't break existing functionality

- **[Test TypeScript SDK](workflows/on-pr-push-ts-sdk.yaml):**  
  Validates SDK changes against existing examples:
  - **Triggers on:** Changes to `sdk/typescript/**` files
  - **Tests:** Examples with locally built SDK and published ABI
  - **Purpose:** Ensures SDK modifications don't break example compatibility

- **[Test Solidity Changes](workflows/on-pr-push-solidity.yaml):**  
  Validates Solidity contract changes against examples:
  - **Triggers on:** Changes to `solidity/**` files
  - **Tests:** Examples with locally built ABI and published SDK
  - **Purpose:** Ensures contract changes don't break example functionality

All checks must pass before PRs can be merged to the main branch.

## Changes Pushed to Main 🌟
Once changes are merged into the `main` branch, workflows prepare the project for production:

- **[Build (push)](workflows/on-push.yml):**  
  Similar to PR checks, this ensures the integrity of the main branch:
  - **Build and Test:** Compiles code and runs tests for all subdirectories using [build.yaml](workflows/build.yaml).

- **[Publish Docker Images](workflows/cross-build-images.yaml):**  
  Produces production-grade, cross-platform Docker images and publishes them to the container registry:
  - **Registry:** `ghcr.io/lf-decentralized-trust-labs`
  - **Images:** `paladin`, `paladin-operator`
  - **Tagging:** Images are tagged with `main`.
  - **Platforms:** `linux/amd64`, `linux/arm64`

- **[Update Documentation](workflows/docs.yaml):**  
  Detects documentation updates and publishes the latest content to the documentation site.

## Release Time 🚀
Paladin follows a two-stage release process to ensure quality and stability:

### Stage 1: Release Candidate (RC) 🧪
Release candidates are created first for testing and validation:

- **[Release Candidate Workflow](workflows/release-candidate.yaml):**  
  Triggered by an RC tag (e.g., `v1.2.3-rc.1`), this workflow creates pre-releases:
  - **[Release Docker Images](workflows/release-images.yaml):**  
    Builds and **publishes Docker images** tagged with the RC version (e.g., `v1.2.3-rc.1`).
    - **Registries:** 
      - `ghcr.io/lf-decentralized-trust-labs`
      - `docker.io/lfdecentralizedtrust`
    - **Images:** `paladin`, `paladin-operator`
    > RC images are **never** tagged as `latest`
  - **[Release Helm Chart](workflows/release-charts.yaml):**
    Packages and **publishes Helm charts** tagged with the RC version.
    > **Includes E2E Testing:** This workflow automatically runs comprehensive end-to-end tests before publishing
  - **[Release Solidity Contracts](workflows/release-solidity-contracts.yaml):**
    Packages contract ABIs and deployment artifacts for distribution.
  - **GitHub Release:** Creates a pre-release with all artifacts

  - **[Test Rollout](workflows/test-rollout.yaml):**  
    **Backwards Compatibility Testing** - Comprehensive validation that ensures smooth version upgrades:
    - **Manual Trigger:** Can be triggered manually with specific version tags (e.g., previous version vs new RC)
    - **Testing Process:**
      1. **Setup:** Creates a Kind cluster and installs the previous version of Paladin
      2. **Initial State:** Runs all examples with the old version to establish baseline functionality
      3. **Rollout:** Upgrades to the new RC version using Helm
      4. **Validation:** Verifies the installation is successful after rollout
      5. **Backwards Compatibility:** Tests that existing data and contracts still work with:
        - Old SDK version (ensures users can continue using existing code)
        - New SDK version (ensures users can upgrade their code)
      6. **Forward Compatibility:** Runs examples with the new SDK version to validate new features
      7. **Cleanup:** Destroys the test cluster
    - **Purpose:** Ensures that users can safely upgrade from the previous version to the new RC without breaking existing functionality or data
    - **Critical for:** Production deployments, user confidence, and release quality assurance

### Stage 2: Final Release 🎯
Once the RC has been tested and validated, the final release can be created:

- **[Release Orchestrator](workflows/release.yaml):**  
  Triggered by a final version tag (e.g., `v1.2.3`), this workflow coordinates the final release:
  - **[Release Docker Images](workflows/release-images.yaml):**  
    Builds and **publishes Docker images** tagged with the release version (e.g., `v1.2.3`) and `latest`.
    - **Registries:** 
      - `ghcr.io/lf-decentralized-trust-labs`
      - `docker.io/lfdecentralizedtrust`
    - **Images:** `paladin`, `paladin-operator`
    > `latest` is configurable 
  - **[Release Helm Chart](workflows/release-charts.yaml):**
    Packages and **publishes Helm charts** to the chart repository tagged with the release version (e.g., `v1.2.3`) and `latest`.
    > **Includes E2E Testing:** This workflow automatically runs comprehensive end-to-end tests before publishing
    > `latest` is configurable 
  - **[Release TypeScript SDK](workflows/release-typescript-sdk.yaml):**  
    Updates and **publishes the TypeScript SDK** to npm:
    - **Package:** `@lfdecentralizedtrust/paladin-sdk`
    - **Registry:** [npm](https://www.npmjs.com/package/@lfdecentralizedtrust/paladin-sdk)
  - **[Release Solidity Contracts](workflows/release-solidity-contracts.yaml):**
    Packages contract ABIs and deployment artifacts for distribution.
  - **GitHub Release:** Creates a final release with all artifacts

### Releasing Options: 
* **Release Candidate:** Trigger the [RC workflow](https://github.com/LF-Decentralized-Trust-labs/paladin/actions/workflows/release-candidate.yaml) via the GitHub Actions interface, specifying the RC version.
* **Release:** Trigger the [release workflow](https://github.com/LF-Decentralized-Trust-labs/paladin/actions/workflows/release.yaml) via the GitHub Actions interface, specifying the final version and selecting the "latest" option if needed.

### Important Release Process Notes:
- **RC Required:** Final releases can only be created if a corresponding RC exists
- **Testing:** Always test RCs thoroughly before promoting to final release
- **Version Consistency:** The RC version must match the final version (e.g., `v1.0.0-rc.1` → `v1.0.0`)


## Manual Actions 🛠️
Workflows can also be triggered manually when needed. Available options include:

- **[Test Rollout](workflows/test-rollout.yaml)** (Version rollout testing)
- **[Release Orchestrator](workflows/release.yaml)** (Final releases)
- **[Release Candidate](workflows/release-candidate.yaml)** (RC releases)
- **[Release Docker Images](workflows/release-images.yaml)**
- **[Release Helm Chart](workflows/release-charts.yaml)**
- **[Release TypeScript SDK](workflows/release-typescript-sdk.yaml)**
- **[Release Solidity Contracts](workflows/release-solidity-contracts.yaml)**
- **[Build Helm Chart](workflows/build-chart.yaml)**
- **[Build Docker Images](workflows/build-image.yaml)**  
- **[Cross-Platform Docker Image Build](workflows/cross-build-images.yaml)**
- **[Build Project](workflows/build.yaml)**
- **[Build (PR)](workflows/on-pr.yaml)**
- **[Build (push)](workflows/on-push.yml)**
- **[Docs Site](workflows/docs.yaml)**

## Additional Workflows

- **[Stale Issues/PRs](workflows/stale.yml):** Automatically marks and closes stale issues and pull requests
- **[Build Workflows](workflows/build-workflows.yaml):** Validates workflow syntax and structure
- **[Check Metadata Changes](workflows/check-metadata-changes.yml):** Prevents version number changes in example metadata
