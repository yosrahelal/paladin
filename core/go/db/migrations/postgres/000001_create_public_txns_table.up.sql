BEGIN;

CREATE TABLE public_txns (
  "signer_nonce"              TEXT            NOT NULL,
  "from"                      TEXT            NOT NULL,
  "nonce"                     BIGINT          NOT NULL,
  "created_at"                TIMESTAMP       NOT NULL,
  "key_handle"                TEXT            NOT NULL,
  "to"                        TEXT,
  "gas"                       BIGINT          NOT NULL,
  "fixed_gas_pricing"         TEXT,
  "value"                     TEXT            NOT NULL,
  "data"                      TEXT,
  "suspended"                 BOOLEAN         NOT NULL,
  PRIMARY KEY("signer_nonce")
);

CREATE UNIQUE INDEX public_txns_from_nonce ON public_txns("from", "nonce");
COMMIT;
