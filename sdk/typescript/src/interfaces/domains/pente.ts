import { PaladinVerifier } from "../../verifier";

export interface IGroupInfo {
  salt: string;
  members: string[];
}

export interface IGroupInfoUnresolved {
  salt: string;
  members: (string | PaladinVerifier)[];
}
