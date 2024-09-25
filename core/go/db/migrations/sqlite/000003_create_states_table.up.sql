CREATE TABLE states (
    "id"               VARCHAR NOT NULL,
    "created"          BIGINT  NOT NULL,
    "domain_name"      VARCHAR,
    "schema"           VARCHAR,
    "contract_address" VARCHAR,
    "data"             VARCHAR,
    "confirm_id"       VARCHAR,
    "spend_id"         VARCHAR,
    PRIMARY KEY ("id"),
    FOREIGN KEY ("domain_name", "schema") REFERENCES schemas ("domain_name", "id") ON DELETE CASCADE
);
CREATE INDEX states_by_domain ON states("domain_name", "schema", "contract_address");
CREATE UNIQUE INDEX states_by_confirm_id ON states("confirm_id");
CREATE UNIQUE INDEX states_by_spend_id ON states("spend_id");

CREATE TABLE state_labels (
    "state"       VARCHAR NOT NULL,
    "label"       VARCHAR NOT NULL,
    "value"       VARCHAR,
    PRIMARY KEY ("state", "label"),
    FOREIGN KEY ("state") REFERENCES states ("id") ON DELETE CASCADE
);
CREATE INDEX state_labels_value ON state_labels("value");

CREATE TABLE state_int64_labels (
    "state"       VARCHAR NOT NULL,
    "label"       VARCHAR NOT NULL,
    "value"       BIGINT,
    PRIMARY KEY ("state", "label"),
    FOREIGN KEY ("state")  REFERENCES states ("id") ON DELETE CASCADE
);
CREATE INDEX state_int64_labels_value ON state_int64_labels("value");
