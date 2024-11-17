-- For SQLite we do not propagate public Tx data in created before migration 13
DROP TABLE IF EXISTS public_txn_bindings;
DROP TABLE IF EXISTS public_submissions;
DROP TABLE IF EXISTS public_completions;
DROP TABLE IF EXISTS public_txns;
DROP TABLE IF EXISTS dispatches;

CREATE TABLE public_txns (
  "pub_txn_id"                INTEGER         PRIMARY KEY AUTOINCREMENT,
  "from"                      TEXT            NOT NULL,
  "nonce"                     BIGINT,
  "created"                   BIGINT          NOT NULL,
  "to"                        TEXT,
  "gas"                       BIGINT          NOT NULL,
  "fixed_gas_pricing"         TEXT,
  "value"                     TEXT,
  "data"                      TEXT,
  "suspended"                 BOOLEAN         NOT NULL
);
CREATE UNIQUE INDEX public_txns_from_nonce ON public_txns("from", "nonce");

CREATE TABLE public_submissions (
  "tx_hash"                   TEXT            NOT NULL,
  "pub_txn_id"                BIGINT          NOT NULL,
  "created"                   BIGINT          NOT NULL,
  "gas_pricing"               TEXT,
  PRIMARY KEY("tx_hash"),
  FOREIGN KEY ("pub_txn_id") REFERENCES public_txns ("pub_txn_id") ON DELETE CASCADE
);
CREATE INDEX public_submissions_pub_txn_id on public_submissions("pub_txn_id");

CREATE TABLE public_completions (
  "pub_txn_id"                INTEGER         NOT NULL,
  "created"                   BIGINT          NOT NULL,
  "tx_hash"                   TEXT            NOT NULL,
  "success"                   BOOLEAN         NOT NULL,
  "revert_data"               TEXT,
  FOREIGN KEY ("pub_txn_id") REFERENCES public_txns ("pub_txn_id") ON DELETE CASCADE,
  PRIMARY KEY("pub_txn_id")
);

CREATE TABLE public_txn_bindings (
  "pub_txn_id"                INTEGER         NOT NULL,
  "transaction"               UUID            NOT NULL,
  "tx_type"                   VARCHAR         NOT NULL,
  PRIMARY KEY ("pub_txn_id"),
  FOREIGN KEY ("pub_txn_id") REFERENCES public_txns ("pub_txn_id") ON DELETE CASCADE
);
CREATE INDEX public_txn_bindings_transaction ON public_txn_bindings("transaction");

CREATE TABLE dispatches (
    "public_transaction_address"  TEXT    NOT NULL,
    "public_transaction_id"       BIGINT  NOT NULL,
    "private_transaction_id"      TEXT    NOT NULL,
    "id"                          TEXT    NOT NULL,
    PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX dispatches_public_private ON dispatches("public_transaction_address","public_transaction_id","private_transaction_id");
