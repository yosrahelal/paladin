import { PentePrivacyGroupHelper } from "./pente";
import bondSubscription from "../abis/BondSubscription.json";
import PaladinClient from "paladin-sdk";

const bondSubscriptionConstructor = bondSubscription.abi.find(
  (entry) => entry.type === "constructor"
);

export interface BondSubscriptionConstructorParams {
  bondAddress_: string;
  units_: string | number;
}

export const newBondSubscription = async (
  pente: PentePrivacyGroupHelper,
  from: string,
  params: BondSubscriptionConstructorParams
) => {
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
}
