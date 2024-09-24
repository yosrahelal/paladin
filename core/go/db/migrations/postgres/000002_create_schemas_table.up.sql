BEGIN;
CREATE TABLE schemas (
    "id"             TEXT    NOT NULL,
    "created"        BIGINT,
    "domain_name"    TEXT,
    "type"           TEXT,
    "signature"      TEXT,
    "definition"     TEXT,
    "labels"         TEXT,
    PRIMARY KEY ("domain_name", "id")
);
COMMIT;