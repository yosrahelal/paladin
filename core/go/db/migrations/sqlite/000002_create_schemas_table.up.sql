CREATE TABLE schemas (
    "id"             VARCHAR NOT NULL,
    "created"        BIGINT,
    "domain_name"    VARCHAR,
    "type"           VARCHAR,
    "signature"      VARCHAR,
    "definition"     VARCHAR,
    "labels"         VARCHAR,
    PRIMARY KEY ("domain_name", "id")
);
