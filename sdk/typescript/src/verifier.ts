import { Algorithms, JsonRpcResult, Verifiers } from "./interfaces";
import PaladinClient from "./paladin";

export class PaladinVerifier {
  constructor(private paladin: PaladinClient, public readonly lookup: string) {}

  toString() {
    return this.lookup;
  }

  resolve(algorithm: Algorithms, verifierType: Verifiers) {
    return this.paladin.resolveVerifier(this.lookup, algorithm, verifierType);
  }

  address() {
    return this.resolve(Algorithms.ECDSA_SECP256K1, Verifiers.ETH_ADDRESS);
  }
}
