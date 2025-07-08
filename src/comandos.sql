-- Estrutura inicial do banco de dados:
DROP TABLE IF EXISTS comments, comments_sanitize, profiles;
CREATE TABLE comments (
	text VARCHAR
);

CREATE TABLE comments_sanitize (
	text VARCHAR
);

CREATE TABLE profiles (
	name VARCHAR,
	description VARCHAR
);

CREATE TABLE IF NOT EXISTS stolen_credentials (
  id SERIAL PRIMARY KEY,
  username VARCHAR NOT NULL,
  password VARCHAR NOT NULL,
  ip VARCHAR NOT NULL,
  accessed_at TIMESTAMP NOT NULL DEFAULT NOW()
);