import PaladinClient, {
  PaladinVerifier,
  PentePrivacyGroup,
  PentePrivateContract,
} from "@lfdecentralizedtrust-labs/paladin-sdk";
import bondTracker from "../abis/BondTracker.json";
import { InvestorList } from "./investorlist";

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
  pente: PentePrivacyGroup,
  from: PaladinVerifier,
  params: BondTrackerConstructorParams
) => {
  const address = await pente.deploy(
    bondTracker.abi,
    bondTracker.bytecode,
    from,
    params
  );
  return address ? new BondTracker(pente, address) : undefined;
};

export class BondTracker extends PentePrivateContract<BondTrackerConstructorParams> {
  constructor(
    protected evm: PentePrivacyGroup,
    public readonly address: string
  ) {
    super(evm, bondTracker.abi, address);
  }

  using(paladin: PaladinClient) {
    return new BondTracker(this.evm.using(paladin), this.address);
  }

  beginDistribution(from: PaladinVerifier, params: BeginDistributionParams) {
    return this.invoke(from, "beginDistribution", params);
  }

  async investorList(from: PaladinVerifier) {
    const result = await this.call(from, "investorList", []);
    return new InvestorList(this.evm, result[0]);
  }
}
