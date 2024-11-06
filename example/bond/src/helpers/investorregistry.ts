import PaladinClient, {
  PentePrivacyGroup,
  PentePrivateContract,
} from "paladin-sdk";
import investorRegistry from "../abis/InvestorRegistry.json";

export interface AddInvestorParams {
  addr: string;
}

export class InvestorRegistry extends PentePrivateContract<{}> {
  constructor(
    protected evm: PentePrivacyGroup,
    public readonly address: string
  ) {
    super(evm, investorRegistry.abi, address);
  }

  using(paladin: PaladinClient) {
    return new InvestorRegistry(this.evm.using(paladin), this.address);
  }

  addInvestor(from: string, params: AddInvestorParams) {
    return this.invoke(from, "addInvestor", params);
  }
}
