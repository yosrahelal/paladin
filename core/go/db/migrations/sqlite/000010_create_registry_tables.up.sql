CREATE TABLE registry_entities (
    "registry"           TEXT    NOT NULL,
    "id"                 TEXT    NOT NULL,
    "name"               TEXT    NOT NULL,
    "parent_id"          TEXT    NOT NULL, -- empty string for root entry (not null)
    "created"            BIGINT  NOT NULL,
    "updated"            BIGINT  NOT NULL,
    "active"             BOOLEAN NOT NULL,
    "block_number"       BIGINT,
    "transaction_index"  INT,
    "log_index"          INT,
    PRIMARY KEY ("registry", "id")
);

-- The name is scoped uniquely within the parent
CREATE UNIQUE INDEX registry_entities_name ON registry_entities("registry", "name", "parent_id");

CREATE TABLE registry_properties (
    "entity_id"          TEXT    NOT NULL,
    "name"               TEXT    NOT NULL,
    "created"            BIGINT  NOT NULL,
    "updated"            BIGINT  NOT NULL,
    "active"             BOOLEAN NOT NULL,
    'value'              TEXT    NOT NULL,
    "block_number"       BIGINT,
    "transaction_index"  INT,
    "log_index"          INT,
    PRIMARY KEY ("registry", "entity_id", "name"),
    FOREIGN KEY ("registry", "entity_id") REFERENCES registry_entities ("registry", "id") ON DELETE CASCADE
);

-- We deliberately do NOT index the values. The values will be large in most cases.
-- Searches should sub-select based on NOT NULL for existence of properties for efficiency.
-- In the future, if we need the ability to search on some values more efficiently we
-- should introduce a distinction of these fields (using a separate indexed properties)
-- rather than indexing all values of all properties (multi-KB X509 certificates etc.)
