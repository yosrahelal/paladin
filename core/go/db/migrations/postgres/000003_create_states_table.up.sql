BEGIN;

CREATE TABLE states (
    "id"               TEXT    NOT NULL,
    "created"          BIGINT  NOT NULL,
    "domain_name"      TEXT,
    "schema"           TEXT,
    "contract_address" TEXT,
    "data"             TEXT,
    "confirm_id"       TEXT,
    "spend_id"         TEXT,
    PRIMARY KEY ("id"),
    FOREIGN KEY ("domain_name", "schema") REFERENCES schemas ("domain_name", "id") ON DELETE CASCADE
);
CREATE INDEX states_by_domain ON states("domain_name", "schema", "contract_address");
CREATE UNIQUE INDEX states_by_confirm_id ON states("confirm_id");
CREATE UNIQUE INDEX states_by_spend_id ON states("spend_id");

CREATE TABLE state_labels (
    "state"       TEXT    NOT NULL,
    "label"       TEXT    NOT NULL,
    "value"       TEXT,
    PRIMARY KEY ("state", "label"),
    FOREIGN KEY ("state") REFERENCES states ("id") ON DELETE CASCADE
);
CREATE INDEX state_labels_value ON state_labels("value");

CREATE TABLE state_int64_labels (
    "state"       TEXT    NOT NULL,
    "label"       TEXT    NOT NULL,
    "value"       BIGINT,
    PRIMARY KEY ("state", "label"),
    FOREIGN KEY ("state")  REFERENCES states ("id") ON DELETE CASCADE
);
CREATE INDEX state_int64_labels_value ON state_int64_labels("value");

COMMIT;