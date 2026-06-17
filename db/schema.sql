-- db/schema.sql — CORE light schema. Pipelines add domain tables via their own schema.sql.
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS target (
  id          INTEGER PRIMARY KEY,
  tid         TEXT NOT NULL UNIQUE,
  raw         TEXT NOT NULL,
  kind        TEXT NOT NULL CHECK (kind IN ('domain','ip','cidr','url','wildcard')),
  first_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS host (
  id          INTEGER PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,          -- FQDN or IP literal
  ip          TEXT,
  source      TEXT,                          -- dns|tls|ptr|subfinder|scope|stub
  first_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS service (
  id          INTEGER PRIMARY KEY,
  ip          TEXT NOT NULL,
  port        INTEGER NOT NULL,
  protocol    TEXT,
  service     TEXT,
  version     TEXT,
  source      TEXT,                          -- naabu|fingerprintx|nerva|stub
  first_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (ip, port)
);

CREATE TABLE IF NOT EXISTS host_target (
  host_id    INTEGER NOT NULL REFERENCES host(id)   ON DELETE CASCADE,
  target_id  INTEGER NOT NULL REFERENCES target(id) ON DELETE CASCADE,
  PRIMARY KEY (host_id, target_id)
);

CREATE TABLE IF NOT EXISTS hypothesis (
  id          INTEGER PRIMARY KEY,
  service_id  INTEGER REFERENCES service(id) ON DELETE CASCADE,
  subject     TEXT,                          -- free pointer to pipeline entities, e.g. "webasset:<url>"
  title       TEXT NOT NULL,
  rationale   TEXT,
  technique   TEXT,
  confidence  TEXT CHECK (confidence IN ('low','medium','high')),
  source      TEXT,                          -- 'stub' | model name
  status      TEXT NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed','confirmed','dismissed')),
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
