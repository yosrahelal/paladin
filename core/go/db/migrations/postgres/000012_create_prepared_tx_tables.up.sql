BEGIN;

CREATE TABLE prepared_txns (
    "id"          UUID       NOT NULL,
    "created"     BIGNUMBER  NOT NULL,
    "transaction" TEXT       NOT NULL,
    "extra_data"  TEXT       ,
    PRIMARY KEY ("id"),
    FOREIGN KEY ("id") REFERENCES transactions ("id") ON DELETE CASCADE
);

CREATE TABLE prepared_txn_states (
    "transaction" UUID       NOT NULL,
    "state"       TEXT       NOT NULL,
    "type"        TEXT       NOT NULL,
    PRIMARY KEY ("transaction", "state", "type"),
    FOREIGN KEY ("transaction") REFERENCES prepared_txns ("id") ON DELETE CASCADE,
    FOREIGN KEY ("state") REFERENCES states ("id") ON DELETE CASCADE
);

COMMIT;