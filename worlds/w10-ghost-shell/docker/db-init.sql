-- GHOST SHELL :: datastore seed
-- Creates the table the reporting API reads. The flag is NOT here - it lives in
-- the ops console's process environment, so reaching the datastore is
-- necessary but not sufficient. The chain ends at code execution.

CREATE TABLE IF NOT EXISTS sessions (
  id       SERIAL PRIMARY KEY,
  operator TEXT NOT NULL,
  token    TEXT NOT NULL,
  created  TIMESTAMPTZ DEFAULT now()
);

INSERT INTO sessions (operator, token)
SELECT 'ops-' || g, md5(g::text)
FROM generate_series(1, 5) g
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS audit (
  id      SERIAL PRIMARY KEY,
  note    TEXT NOT NULL,
  at      TIMESTAMPTZ DEFAULT now()
);

INSERT INTO audit (note) VALUES ('datastore seeded'), ('ops console online');
