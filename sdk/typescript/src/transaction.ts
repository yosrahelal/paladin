import PaladinClient from "./paladin";

export class TransactionWrapper {
  constructor(
    protected paladin: PaladinClient,
    public readonly id: string | Promise<string>
  ) {}

  toString() {
    return this.id;
  }

  async waitForReceipt(waitMs = 5000, full = false) {
    return this.paladin.pollForReceipt(await this.id, waitMs, full);
  }
}
