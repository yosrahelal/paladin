BEGIN;

CREATE TABLE pgroup_msgs (
  "local_seq"                 BIGINT          GENERATED ALWAYS AS IDENTITY,
  "domain"                    TEXT            NOT NULL,
  "group"                     TEXT            NOT NULL,
  "sent"                      BIGINT          NOT NULL,
  "received"                  BIGINT          NOT NULL,
  "id"                        UUID            NOT NULL,
  "cid"                       UUID            ,
  "topic"                     TEXT            NOT NULL,
  "data"                      TEXT            NOT NULL,
  FOREIGN KEY ("domain", "group") REFERENCES privacy_groups ("domain", "id") ON DELETE CASCADE
);
CREATE UNIQUE INDEX pgroup_msgs_id ON pgroup_msgs ("id");
CREATE INDEX pgroup_msgs_cid ON pgroup_msgs ("cid");
CREATE INDEX pgroup_msgs_group ON pgroup_msgs("domain","group");

COMMIT;