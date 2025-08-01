import { BigNumberish, ethers } from "ethers";
import { HexString } from "ethers/lib.commonjs/utils/data";
import { PublicTxOptions } from ".";

export interface IPrivacyGroupInput {
  domain: string;
  members: string[];
  name: string;
  configuration?: Record<string, string | undefined>;
  properties?: Record<string, string | undefined>;
  transactionOptions?: IPrivacyGroupTXOptions;
}

export interface IPrivacyGroupResume {
  id: string;
}

export interface IPrivacyGroupTXOptions extends PublicTxOptions {
  idempotencyKey?: string;
}

export interface IPrivacyGroup {
  id: string;
  domain: string;
  created: string;
  name: string;
  members: string[];
  properties: Record<string, string>;
  configuration: Record<string, string>;
  contractAddress?: string;
  genesisTransaction?: string;
  genesisSchema?: string;
  genesisSalt?: string;
}

export interface IPrivacyGroupEVMTX {
  from: string;
  to?: string;
  gas?: BigNumberish;
  value?: BigNumberish;
  input?: unknown;
  function?: ethers.JsonFragment;
  bytecode?: HexString;
}

export interface IPrivacyGroupEVMTXInput extends IPrivacyGroupEVMTX {
  idempotencyKey?: string;
  domain: string;
  group: string;
  publicTxOptions?: PublicTxOptions;
}

export interface IPrivacyGroupEVMCall extends IPrivacyGroupEVMTX {
  domain: string;
  group: string;
  dataFormat?: string;
}