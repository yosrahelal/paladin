CREATE TABLE prepared_txns (
    "id"          UUID       NOT NULL,
    "created"     BIGINT     NOT NULL,
    "transaction" VARCHAR    NOT NULL,
    "extra_data"  VARCHAR    ,
    PRIMARY KEY ("id"),
    FOREIGN KEY ("id") REFERENCES transactions ("id") ON DELETE CASCADE
);

CREATE TABLE prepared_txn_states (
    "transaction" UUID       NOT NULL,
    "domain_name" VARCHAR,
    "state"       VARCHAR    NOT NULL,
    "state_idx"   INT        NOT NULL,
    "type"        VARCHAR    NOT NULL,
    PRIMARY KEY ("transaction", "type", "state_idx"),
    FOREIGN KEY ("transaction") REFERENCES prepared_txns ("id") ON DELETE CASCADE,
    FOREIGN KEY ("domain_name","state") REFERENCES states ("domain_name","id") ON DELETE CASCADE
);

