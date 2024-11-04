import * as uuid from "uuid";

export function encodeHex(data: string) {
  return "0x" + Buffer.from(data, "utf8").toString("hex");
}

export function newTransactionId() {
  return encodeHex(uuid.v4()) + "00000000000000000000000000000000";
}
