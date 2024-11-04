import { PentePrivacyGroupHelper } from "./pente";
import bondTracker from "../abis/BondTracker.json";
import PaladinClient from "paladin-sdk";

const bondTrackerConstructor = bondTracker.abi.find(
  (entry) => entry.type === "constructor"
);

export interface BondTrackerConstructorParams {
  name: string;
  symbol: string;
  custodian: string;
  publicTracker: string;
}

export interface BeginDistributionParams {
  discountPrice: string | number;
  minimumDenomination: string | number;
}

export const newBondTracker = async (
  pente: PentePrivacyGroupHelper,
  from: string,
  params: BondTrackerConstructorParams
) => {
  const receipt = await pente.deploy(
    from,
    bondTrackerConstructor,
    bondTracker.bytecode,
    params
  );
  return receipt?.domainReceipt?.receipt.contractAddress === undefined
    ? undefined
    : new BondTrackerHelper(
        pente,
        receipt.domainReceipt.receipt.contractAddress
      );
};

export class BondTrackerHelper {
  constructor(
    private pente: PentePrivacyGroupHelper,
    public readonly address: string
  ) {}

  using(paladin: PaladinClient) {
    return new BondTrackerHelper(this.pente.using(paladin), this.address);
  }

  async beginDistribution(from: string, params: BeginDistributionParams) {
    const beginDistributionMethod = bondTracker.abi.find(
      (entry) => entry.name === "beginDistribution"
    );
    return this.pente.invoke(
      from,
      this.address,
      beginDistributionMethod,
      params
    );
  }
}
