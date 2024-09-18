CREATE TABLE abis (
  "hash"                      TEXT            NOT NULL,
  "created"                   BIGINT          NOT NULL,
  "abi"                       TEXT            NOT NULL,
  "devdocs"                   TEXT,   
  "metadata"                  TEXT,   
  PRIMARY KEY ("hash")
);
CREATE INDEX abis_created ON abis("created");

CREATE TABLE abi_errors (
  "selector"                  VARCHAR         NOT NULL,
  "abi_hash"                  VARCHAR         NOT NULL,
  "definition"                VARCHAR         NOT NULL,
  PRIMARY KEY ("abi_hash", "selector"),
  FOREIGN KEY ("abi_hash") REFERENCES abis ("hash") ON DELETE CASCADE
);

CREATE TABLE transactions (
  "id"                        UUID            NOT NULL,
  "idempotency_key"           TEXT,   
  "created"                   BIGINT          NOT NULL,
  "abi_ref"                   TEXT            NOT NULL,
  "function"                  TEXT,   
  "domain"                    TEXT,   
  "from"                      TEXT            NOT NULL,
  "to"                        TEXT,   
  "data"                      TEXT,   
  PRIMARY KEY ("id"),
  FOREIGN KEY ("abi_ref") REFERENCES abis ("hash") ON DELETE CASCADE
);
CREATE INDEX transactions_created ON transactions("created");
CREATE INDEX transactions_domain ON transactions("domain");
CREATE INDEX transactions_idempotency_key ON transactions("idempotency_key");

CREATE TABLE transaction_deps (
  "transaction"               UUID            NOT NULL,
  "depends_on"                UUID            NOT NULL,
  PRIMARY KEY ("transaction","depends_on"),
  FOREIGN KEY ("transaction") REFERENCES transactions ("id") ON DELETE CASCADE
);
CREATE INDEX transaction_deps_depends_on ON transactions("depends_on");

CREATE TABLE transaction_receipts (
  "transaction"               UUID            NOT NULL,
  "status"                    TEXT            NOT NULL,
  "tx_hash"                   TEXT,
  PRIMARY KEY ("transaction"),
  FOREIGN KEY ("transaction") REFERENCES transactions ("id") ON DELETE CASCADE
);
CREATE INDEX transaction_receipts_tx_hash ON transactions("tx_hash");