import { PentePrivacyGroupHelper } from "./pente";
import investorRegistry from "../abis/InvestorRegistry.json";
import PaladinClient from "paladin-sdk";

export interface AddInvestorParams {
  addr: string;
}

export class InvestorRegistryHelper {
  constructor(
    private pente: PentePrivacyGroupHelper,
    public readonly address: string
  ) {}

  using(paladin: PaladinClient) {
    return new InvestorRegistryHelper(this.pente.using(paladin), this.address);
  }

  async addInvestor(from: string, params: AddInvestorParams) {
    const method = investorRegistry.abi.find(
      (entry) => entry.name === "addInvestor"
    );
    if (method === undefined) {
      throw new Error("Method 'addInvestor' not found");
    }
    return this.pente.invoke(from, this.address, method, params);
  }
}
