BEGIN;

CREATE TABLE registry_transport_details (
    "node"               TEXT    NOT NULL,
    "registry"           TEXT    NOT NULL,
    "transport"          TEXT    NOT NULL,
    "details"            TEXT    NOT NULL,
    PRIMARY KEY ("registry","node","transport")
);

COMMIT;