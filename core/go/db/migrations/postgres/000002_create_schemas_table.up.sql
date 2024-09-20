BEGIN;
CREATE TABLE schemas (
    "id"             TEXT    NOT NULL,
    "created_at"     BIGINT,
    "domain_name"    TEXT,
    "type"           TEXT,
    "signature"      TEXT,
    "definition"     TEXT,
    "labels"         TEXT,
    PRIMARY KEY ("domain_name", "id")
);
COMMIT;