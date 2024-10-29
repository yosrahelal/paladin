CREATE TABLE prepared_txns (
    "id"          UUID       NOT NULL,
    "created"     BIGNUMBER  NOT NULL,
    "transaction" VARCHAR    NOT NULL,
    "extra_data"  VARCHAR    ,
    PRIMARY KEY ("id"),
    FOREIGN KEY ("id") REFERENCES transactions ("id") ON DELETE CASCADE
);

CREATE TABLE prepared_txn_states (
    "transaction" UUID       NOT NULL,
    "state"       VARCHAR    NOT NULL,
    "state_idx"   INT        NOT NULL,
    "type"        VARCHAR    NOT NULL,
    PRIMARY KEY ("transaction", "state", "type"),
    FOREIGN KEY ("transaction") REFERENCES prepared_txns ("id") ON DELETE CASCADE,
    FOREIGN KEY ("state") REFERENCES states ("id") ON DELETE CASCADE
);

