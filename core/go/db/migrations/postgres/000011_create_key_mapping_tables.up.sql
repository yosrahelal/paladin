BEGIN;

CREATE TABLE key_paths (
    "parent"             VARCHAR         NOT NULL,
    "index"              BIGINT          NOT NULL,
    "path"               VARCHAR         NOT NULL,
    PRIMARY KEY ("parent", "index")
);

CREATE UNIQUE INDEX key_paths_path ON key_paths ("path");

CREATE TABLE key_mappings (
    "identifier"         VARCHAR         NOT NULL,
    "wallet"             VARCHAR         NOT NULL,
    "key_handle"         VARCHAR         NOT NULL,
    PRIMARY KEY ("identifier"),
    FOREIGN KEY ("identifier") REFERENCES key_paths ("path") ON DELETE CASCADE
);

CREATE UNIQUE INDEX key_mappings_identifier ON key_mappings ("identifier");

CREATE TABLE key_verifiers (
    "identifier"         VARCHAR         NOT NULL,
    "algorithm"          VARCHAR         NOT NULL,
    "type"               VARCHAR         NOT NULL,
    "verifier"           VARCHAR         NOT NULL,
    PRIMARY KEY ("identifier", "algorithm", "verifier_typetype"),
    FOREIGN KEY ("identifier") REFERENCES key_paths ("identifier") ON DELETE CASCADE
);

COMMIT;
