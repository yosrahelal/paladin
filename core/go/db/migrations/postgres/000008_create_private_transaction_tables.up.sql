BEGIN;

CREATE TABLE dispatches (
    "public_transaction_address"  TEXT    NOT NULL,
    "public_transaction_nonce"    BIGINT  NOT NULL,
    "private_transaction_id"      TEXT    NOT NULL,
    "id"                          TEXT    NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX dispatches_public_private ON dispatches("public_transaction_address","public_transaction_nonce","private_transaction_id");

COMMIT;

