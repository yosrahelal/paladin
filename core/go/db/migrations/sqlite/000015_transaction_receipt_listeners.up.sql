CREATE TABLE transaction_receipt_listeners (
    "name"           TEXT       NOT NULL,
    "filters"        TEXT       NOT NULL,
    "options"        TEXT       NOT NULL,
    PRIMARY KEY("name")
);

CREATE TABLE transaction_receipt_blocks (
    "listener"           TEXT    NOT NULL,
    "source"             TEXT    NOT NULL,
    "transaction"        UUID    NOT NULL,
    PRIMARY KEY ("listener", "contract_address"),
    FOREIGN KEY ("listener") REFERENCES transaction_receipt_listeners ("name") ON DELETE CASCADE
);

CREATE INDEX transaction_receipt_blocks_txid ON transaction_receipt_blocks("transaction");

CREATE TABLE transaction_receipt_checkpoints (
    "listener"           TEXT    NOT NULL,
    "sequence"           BIGINT  NOT NULL,
    PRIMARY KEY ("listener"),
    FOREIGN KEY ("listener") REFERENCES transaction_receipt_listeners ("name") ON DELETE CASCADE
);
