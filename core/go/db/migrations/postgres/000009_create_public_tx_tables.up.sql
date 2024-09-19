BEGIN;

CREATE TABLE public_transactions (
  id                           UUID            PRIMARY KEY,
  created                      BIGINT          NOT NULL,
  updated                      BIGINT          NOT NULL,
  status                       VARCHAR(65)     NOT NULL, -- indexed field, update to this field should be limited
  sub_status                   VARCHAR(65)     NOT NULL, -- not indexed
  tx_from                      TEXT            NOT NULL,
  tx_to                        TEXT,
  tx_nonce                     BIGINT          NOT NULL,
  tx_gas_limit                 BIGINT,
  tx_value                     BIGINT,
  tx_gas_price                 BIGINT,
  tx_max_fee_per_gas           BIGINT,
  tx_max_priority_fee_per_gas  BIGINT,
  tx_data                      TEXT            NOT NULL,
  tx_hash                      TEXT            NOT NULL,
  first_submit                 BIGINT,
  last_submit                  BIGINT,
  error_message                TEXT            NOT NULL
);

CREATE UNIQUE INDEX public_transactions_id ON public_transactions(id);
CREATE UNIQUE INDEX public_transactions_nonce ON public_transactions(tx_from, tx_nonce);
CREATE UNIQUE INDEX public_transactions_status ON public_transactions(status);
-- CREATE INDEX public_transactions_hash ON public_transactions(tx_hash);

CREATE TABLE public_transaction_hashes (
    "public_tx_id"  UUID    NOT NULL,
    "hash"          TEXT    PRIMARY KEY,
    FOREIGN KEY ("public_tx_id") REFERENCES public_transactions ("id") ON DELETE CASCADE
);

COMMIT;