BEGIN;

DROP INDEX transaction_receipts_tx_hash;
DROP INDEX transaction_receipts_source;

ALTER TABLE transaction_receipts RENAME TO  transaction_receipts_old;

-- We need to add the sequence column, but the easiest thing is to simply re-create the table
CREATE TABLE transaction_receipts (
  "sequence"                  BIGINT          GENERATED ALWAYS AS IDENTITY,
  "transaction"               UUID            NOT NULL, -- note there is no foreign key to transactions here - we can have receipts for TXs that we do not know locally
  "domain"                    VARCHAR         NOT NULL, -- empty string for public
  "indexed"                   BIGINT          NOT NULL,
  "success"                   BOOLEAN         NOT NULL,
  "failure_message"           VARCHAR,
  "revert_data"               VARCHAR,
  "tx_hash"                   VARCHAR,
  "tx_index"                  INT,
  "log_index"                 INT,
  "source"                    VARCHAR,
  "block_number"              BIGINT,
  "contract_address"          VARCHAR
);
CREATE UNIQUE INDEX transaction_receipts_tx_id ON transaction_receipts ("transaction");
CREATE INDEX transaction_receipts_tx_hash ON transaction_receipts ("tx_hash");
CREATE INDEX transaction_receipts_source ON transaction_receipts ("source");

-- Copy any existing data over
INSERT INTO transaction_receipts (
  "transaction",
  "domain",
  "indexed",
  "success",
  "failure_message",
  "revert_data",
  "tx_hash",
  "tx_index",
  "log_index",
  "source",
  "block_number",
  "contract_address"
) SELECT
  "transaction",
  "domain",
  "indexed",
  "success",
  "failure_message",
  "revert_data",
  "tx_hash",
  "tx_index",
  "log_index",
  "source",
  "block_number",
  "contract_address"
  FROM transaction_receipts_old;

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
    PRIMARY KEY ("listener", "source"),
    FOREIGN KEY ("listener") REFERENCES transaction_receipt_listeners ("name") ON DELETE CASCADE
);

CREATE INDEX transaction_receipt_blocks_txid ON transaction_receipt_blocks("transaction");

CREATE TABLE transaction_receipt_checkpoints (
    "listener"           TEXT    NOT NULL,
    "sequence"           BIGINT  NOT NULL,
    PRIMARY KEY ("listener"),
    FOREIGN KEY ("listener") REFERENCES transaction_receipt_listeners ("name") ON DELETE CASCADE
);


COMMIT;