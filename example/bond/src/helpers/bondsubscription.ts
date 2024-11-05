import { PentePrivacyGroupHelper } from "./pente";
import bondSubscription from "../abis/BondSubscription.json";
import PaladinClient from "paladin-sdk";

const bondSubscriptionConstructor = bondSubscription.abi.find(
  (entry) => entry.type === "constructor"
);

export interface BondSubscriptionConstructorParams {
  bondAddress_: string;
  units_: string | number;
  custodian_: string;
}

export interface PreparePaymentParams {
  to: string;
  encodedCall: string;
}

export interface PrepareBondParams {
  to: string;
  encodedCall: string;
}

export interface DistributeParams {
  units_: string | number;
}

export const newBondSubscription = async (
  pente: PentePrivacyGroupHelper,
  from: string,
  params: BondSubscriptionConstructorParams
) => {
  if (bondSubscriptionConstructor === undefined) {
    throw new Error("Bond subscription constructor not found");
  }
  const receipt = await pente.deploy(
    from,
    bondSubscriptionConstructor,
    bondSubscription.bytecode,
    params
  );
  return receipt?.domainReceipt?.receipt.contractAddress === undefined
    ? undefined
    : new BondSubscriptionHelper(
        pente,
        receipt.domainReceipt.receipt.contractAddress
      );
};

export class BondSubscriptionHelper {
  constructor(
    private pente: PentePrivacyGroupHelper,
    public readonly address: string
  ) {}

  using(paladin: PaladinClient) {
    return new BondSubscriptionHelper(this.pente.using(paladin), this.address);
  }

  async preparePayment(from: string, params: PreparePaymentParams) {
    const method = bondSubscription.abi.find(
      (entry) => entry.name === "preparePayment"
    );
    if (method === undefined) {
      throw new Error("Method 'preparePayment' not found");
    }
    return this.pente.invoke(from, this.address, method, params);
  }

  async prepareBond(from: string, params: PrepareBondParams) {
    const method = bondSubscription.abi.find(
      (entry) => entry.name === "prepareBond"
    );
    if (method === undefined) {
      throw new Error("Method 'prepareBond' not found");
    }
    return this.pente.invoke(from, this.address, method, params);
  }

  async distribute(from: string, params: DistributeParams) {
    const method = bondSubscription.abi.find(
      (entry) => entry.name === "distribute"
    );
    if (method === undefined) {
      throw new Error("Method 'distribute' not found");
    }
    return this.pente.invoke(from, this.address, method, params);
  }
}
