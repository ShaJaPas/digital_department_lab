CREATE TABLE checkpoints (
  checkpoint_id SERIAL PRIMARY KEY,
  checkpoint_name VARCHAR(255) UNIQUE NOT NULL
);
