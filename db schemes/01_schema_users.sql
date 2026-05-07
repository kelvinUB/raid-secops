CREATE EXTENSION IF NOT EXISTS pgcrypto;

DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(100) NOT NULL UNIQUE,
    password_hash TEXT         NOT NULL,
    role          VARCHAR(20)  NOT NULL CHECK (role IN ('analyst', 'engineer', 'grc')),
    full_name     VARCHAR(150) NOT NULL,
    email         VARCHAR(200),
    is_active     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_login    TIMESTAMPTZ
);

INSERT INTO users (username, password_hash, role, full_name, email)
VALUES
  (
    'r.reddy',
    crypt('analyst123', gen_salt('bf', 12)),
    'analyst',
    'Raghu Reddy',
    'r.reddy@raid-secops.local'
  ),
  (
    'k.magora',
    crypt('engineer123', gen_salt('bf', 12)),
    'engineer',
    'Kelvin Magora',
    'k.magora@raid-secops.local'
  ),
  (
    'f.sagayaraj',
    crypt('grc123', gen_salt('bf', 12)),
    'grc',
    'Francina Sagayaraj',
    'f.sagayaraj@raid-secops.local'
  ),
  (
    'b.bindu',
    crypt('analyst123', gen_salt('bf', 12)),
    'analyst',
    'Bipin Bindu',
    'b.bindu@raid-secops.local'
  ),
  (
    'a.kasala',
    crypt('engineer123', gen_salt('bf', 12)),
    'engineer',
    'Aditya Kasala',
    'a.kasala@raid-secops.local'
  ),
  (
    'r.mashinge',
    crypt('grc123', gen_salt('bf', 12)),
    'grc',
    'Ruvimbo Mashinge',
    'r.mashinge@raid-secops.local'
  );

SELECT id, username, role, full_name, is_active, created_at FROM users;