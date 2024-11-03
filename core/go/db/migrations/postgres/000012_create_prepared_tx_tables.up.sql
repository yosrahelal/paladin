BEGIN;

CREATE TABLE prepared_txns (
    "id"          UUID       NOT NULL,
    "created"     BIGINT     NOT NULL,
    "domain"      TEXT       NOT NULL,
    "to"          TEXT       ,
    "transaction" TEXT       NOT NULL,
    "metadata"    TEXT       ,
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


CREATE TABLE prepared_txn_distributions (
    "created"           BIGINT  NOT NULL,
    "prepared_txn_id"   UUID    NOT NULL,
    "domain_name"       TEXT    NOT NULL,
    "contract_address"  TEXT    NOT NULL,
    "identity_locator"  TEXT    NOT NULL,
    "id"                UUID    NOT NULL,
    PRIMARY KEY ("id"),
    FOREIGN KEY ("prepared_txn_id") REFERENCES prepared_txns ("id") ON DELETE CASCADE
);

CREATE INDEX prepared_txn_distributions_created ON prepared_txn_distributions("created");
CREATE UNIQUE INDEX prepared_txn_distributions_prepared_txn_identity ON prepared_txn_distributions("prepared_txn_id","identity_locator");

CREATE TABLE prepared_txn_distribution_acknowledgments (
    "prepared_txn_distribution" UUID    NOT NULL,
    "id"                        UUID    NOT NULL,
    PRIMARY KEY ("id"),
    FOREIGN KEY ("prepared_txn_distribution") REFERENCES prepared_txn_distributions ("id") ON DELETE CASCADE
);

CREATE UNIQUE INDEX prepared_txn_distribution_acknowledgments_prepared_txn_distribution ON prepared_txn_distribution_acknowledgments("prepared_txn_distribution");

COMMIT;