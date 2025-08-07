BEGIN;

CREATE TABLE chained_private_txns (
  "transaction"               UUID            NOT NULL REFERENCES transactions ("id") ON DELETE CASCADE,
  "chained_transaction"       UUID            NOT NULL REFERENCES transactions ("id") ON DELETE CASCADE,
  PRIMARY KEY ("transaction", "chained_transaction")
);

COMMIT;
