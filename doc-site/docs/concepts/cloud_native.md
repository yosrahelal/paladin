Paladin provides a single fast-starting runtime architecture ideal for packaging in to a microservice architecture alongside blockchain and application components. 

Internally it is componentized with gRPC boundaries between separate components (including Golang, Java and WebAssembly), allowing high scale deployments to individual scale components as microservices if required.

Paladin runs completely independently to your blockchain nodes, and uses a Database for state storage. That database can be embedded for development, or a reliable HA deployment of PostgreSQL for production.

### Kubernetes operator and quickstart

As a cloud native OSS project, Paladin is supplied with a Kubernetes operator used throughout development and testing of the Paladin project itself.

![Paladin deployment model](../images/paladin_deployment.svg)

The quickstart uses this operator along with Kind to build a complete 3-node network on your laptop, and to do this the operator also supports building a fully functional test blockchain network using another great project from the Linux Foundation Decentralized Trust family - [Besu](https://github.com/hyperledger/besu).

The default operator sample configuration during startup orchestrates:

- Creating a Genesis config and Besu network
    - Builds a 3-node Besu network with all three nodes as QBFT validators
    - 100ms block time, with 10s empty block period (low latency for testing and development)
- Creating three individual Paladin nodes
    - Creating a PostgreSQL database for each Paladin node (co-located as a sidecar for testing and development)
    - Generating an MTLS certificate for each node using CertManager (self-signed - see registry below)
    - Building a HD Wallet key store for each node, backed by a k8s secret
    - Orchestrating the restart of the Paladin nodes as configuration changes during initialization
- Deploying the Smart Contracts for three Privacy Domains
    - `Pente` - factory contract for Private EVM Privacy Group contracts
    - `Noto` - factory contract for Notarized token contracts
    - `Zeto` - multiple (18 and counting) contracts with inter-dependencies managed to implement multiple ZKP token types
- Deploying a registry and automating registration
    - Smart contract backed registry with simple operator model for root identities
    - Node identities self-register their endpoint details
    - Mutual TLS is automatically configured between nodes via registry publication
