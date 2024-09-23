CREATE TABLE public_txns (
  "signer_nonce"              VARCHAR         NOT NULL,
  "from"                      VARCHAR         NOT NULL,
  "nonce"                     BIGINT          NOT NULL,
  "created_at"                TIMESTAMP       NOT NULL,
  "key_handle"                VARCHAR         NOT NULL,
  "to"                        VARCHAR,
  "gas"                       BIGINT          NOT NULL,
  "fixed_gas_pricing"         VARCHAR,
  "value"                     VARCHAR         NOT NULL,
  "data"                      VARCHAR,
  "suspended"                 BOOLEAN         NOT NULL,
  PRIMARY KEY("signer_nonce")
);

CREATE UNIQUE INDEX public_txns_from_nonce ON public_txns("from", "nonce");
