CREATE TABLE states (
    "id"               VARCHAR NOT NULL,
    "created"          BIGINT  NOT NULL,
    "domain_name"      VARCHAR,
    "schema"           VARCHAR,
    "contract_address" VARCHAR,
    "data"             VARCHAR,
    PRIMARY KEY ("id"),
    FOREIGN KEY ("domain_name", "schema") REFERENCES schemas ("domain_name", "id") ON DELETE CASCADE
);
CREATE INDEX states_by_domain ON states("domain_name", "schema", "contract_address");

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
