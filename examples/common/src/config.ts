import { PaladinConfig } from "@lfdecentralizedtrust-labs/paladin-sdk";
import https from "https"; // Kept for the user example

/**
 * Defines the connectivity information for a single network node.
 */
export interface NodeConnection {
  name: string; // A human-readable name for logging, e.g., "Node 1" or "Central Bank"
  verifierName: string; // The verifier identifier, e.g., "user@node1"
  clientOptions: PaladinConfig; // The options for the PaladinClient constructor
}

/**
 * Default configuration for local development
 */
const nodeConnections: NodeConnection[] = [
  {
    name: "Node 1",
    verifierName: "user@node1",
    clientOptions: { url: "http://127.0.0.1:31548" },
  },
  {
    name: "Node 2",
    verifierName: "user@node2",
    clientOptions: { url: "http://127.0.0.1:31648" },
  },
  {
    name: "Node 3",
    verifierName: "user@node3",
    clientOptions: { url: "http://127.0.0.1:31748" },
  },
];


/*

// Here is an example of a config for a remote environment
// Change the names, urls, and auth headers to match your environment

const nodeConnections: NodeConnection[] = [
  {
    name: "Node 1",
    verifierName: "user@node1",
    clientOptions: {
      url: "https://evm-node-1.com/jsonrpc",
      requestConfig: {
        headers: {
          Authorization: "Basic ABCD"
        },
        httpsAgent: new https.Agent({ rejectUnauthorized: false })
      }
    },
  },
  {
    name: "Node 2",
    verifierName: "user@node1",
    clientOptions: {
      url: "https://evm-node-2.com/jsonrpc",
      requestConfig: {
        headers: {
          Authorization: "Basic ABCD"
        },
        httpsAgent: new https.Agent({ rejectUnauthorized: false })
      }
    },
  },
  {
    name: "Node 3",
    verifierName: "user@node3",
    clientOptions: {
      url: "https://evm-node-3.com/jsonrpc",
      requestConfig: {
        headers: {
          Authorization: "Basic ABCD"
        },
        httpsAgent: new https.Agent({ rejectUnauthorized: false })
      }
    },
  },
];
*/

// Export the default configuration (local development)
export default nodeConnections;

// Export both configurations for flexibility
export { nodeConnections };