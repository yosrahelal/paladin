import { IStateBase } from "./states";
import { ethers } from "ethers";

export interface IBlock {
  number: number;
  hash: string;
  timestamp: string;
}

export enum TransactionType {
  PUBLIC = "public",
  PRIVATE = "private",
}

export interface ITransactionBase {
  type: TransactionType;
  domain?: string;
  function: string;
  from: string;
  to?: string;
  data: {
    [key: string]: any;
  };
}

export interface ITransaction extends ITransactionBase {
  id: string;
  created: string;
  abiReference: string;
}

export interface IPreparedTransaction {
  id: string;
  domain: string;
  to: string;
  transaction: ITransactionBase & {
    abiReference: string;
  };
  states: {
    spent?: IStateBase[];
    read?: IStateBase[];
    confirmed?: IStateBase[];
    info?: IStateBase[];
  };
  metadata: any;
}

export interface ITransactionInput extends ITransactionBase {
  abiReference?: string;
  abi?: ethers.InterfaceAbi;
  bytecode?: string;
}

export interface ITransactionCall extends ITransactionInput {}

export interface ITransactionReceipt {
  blockNumber: number;
  id: string;
  success: boolean;
  transactionHash: string;
  source: string;
  contractAddress?: string;
  domainReceipt?: {
    receipt: {
      contractAddress?: string;
    };
  };
}

export interface ITransactionStates {
  none?: boolean;
  spent?: IStateBase[];
  read?: IStateBase[];
  confirmed?: IStateBase[];
  info?: IStateBase[];
  unavailable?: {
    spent?: string[];
    read?: string[];
    confirmed?: string[];
    info?: string[];
  };
}

export interface ITransactionDependencies {
  dependsOn: string[];
  prereqOf: string[];
}

export interface IPublicTxWithBinding {
  to?: string;
  data?: string;
  from: string;
  nonce: string;
  created: string;
  completedAt?: string;
  transactionHash?: string;
  success?: boolean;
  revertData?: string;
  submissions?: IPublicTxSubmissionData[];
  activity?: ITransactionActivityRecord[];
  gas?: string;
  value?: string;
  maxPriorityFeePerGas?: string;
  maxFeePerGas?: string;
  gasPrice?: string;
  transaction: string;
  transactionType: TransactionType;
}

export interface IPublicTxSubmissionData {
  time: string;
  transactionHash: string;
  maxPriorityFeePerGas?: string;
  maxFeePerGas?: string;
  gasPrice?: string;
}

export interface ITransactionActivityRecord {
  time: string;
  message: string;
}

export enum TransactionType {
  Private = "private",
  Public = "public",
}
