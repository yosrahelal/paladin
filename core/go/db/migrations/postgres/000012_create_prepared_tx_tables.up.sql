BEGIN;

CREATE TABLE prepared_txns (
    "id"          UUID       NOT NULL,
    "created"     BIGINT     NOT NULL,
    "domain"      TEXT       NOT NULL,
    "to"          TEXT       ,
    "transaction" TEXT       NOT NULL,
    "extra_data"  TEXT       ,
    PRIMARY KEY ("id")
    -- FOREIGN KEY ("id") REFERENCES transactions ("id") ON DELETE CASCADE
);

CREATE INDEX prepared_txns_domain_to ON prepared_txns("domain", "to");
CREATE INDEX prepared_txns_created ON  prepared_txns("created");

CREATE TABLE prepared_txn_states (
    "transaction" UUID       NOT NULL,
    "domain_name" VARCHAR,
    "state"       TEXT       NOT NULL,
    "state_idx"   INT        NOT NULL,
    "type"        TEXT       NOT NULL,
    PRIMARY KEY ("transaction", "type", "state_idx"),
    FOREIGN KEY ("transaction") REFERENCES prepared_txns ("id") ON DELETE CASCADE,
    FOREIGN KEY ("domain_name","state") REFERENCES states ("domain_name","id") ON DELETE CASCADE
);

COMMIT;