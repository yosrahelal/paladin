import PaladinClient from "paladin-sdk";
import bondTracker from "../abis/BondTracker.json";
import { InvestorRegistryHelper } from "./investorregistry";
import { PentePrivacyGroupHelper } from "./pente";

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
  if (bondTrackerConstructor === undefined) {
    throw new Error("Bond tracker constructor not found");
  }
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
    const method = bondTracker.abi.find(
      (entry) => entry.name === "beginDistribution"
    );
    if (method === undefined) {
      throw new Error("Method 'beginDistribution' not found");
    }
    return this.pente.invoke(from, this.address, method, params);
  }

  async investorRegistry(from: string) {
    const method = bondTracker.abi.find(
      (entry) => entry.name === "investorRegistry"
    );
    if (method === undefined || method.outputs === undefined) {
      throw new Error("Method 'investorRegistry' not found");
    }
    const result = await this.pente.call(from, this.address, method, []);
    return new InvestorRegistryHelper(this.pente, result[0]);
  }
}
