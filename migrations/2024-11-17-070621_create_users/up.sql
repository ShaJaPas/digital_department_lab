CREATE TABLE roles (
  role_id SERIAL PRIMARY KEY,
  role_name VARCHAR(255) UNIQUE NOT NULL
);

CREATE TABLE users (
  user_id SERIAL PRIMARY KEY,
  username VARCHAR(255) UNIQUE NOT NULL,
  full_name VARCHAR(255) NOT NULL,
  password_hash VARCHAR(256) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  is_active BOOLEAN DEFAULT TRUE,
  role_id INTEGER REFERENCES roles(role_id)
);

INSERT INTO roles (role_id, role_name)
VALUES (1, 'admin')
ON CONFLICT (role_name) DO NOTHING;

INSERT INTO roles (role_id, role_name)
VALUES (2, 'user')
ON CONFLICT (role_name) DO NOTHING;

INSERT INTO users (username, full_name, password_hash, email, role_id)
VALUES ('admin', 'Admin A.A.', '$argon2id$v=19$m=19456,t=2,p=1$REVGQVVMVF9TQUxU$l93uinS/1qPqsTck9rULOdsUU535uwZrrXAY4BUch6c', 'admin@example.com', 1)
ON CONFLICT (username) DO NOTHING;

