export function encodeHex(data: string) {
  return "0x" + Buffer.from(data, "utf8").toString("hex");
}
