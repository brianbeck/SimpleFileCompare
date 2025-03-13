-- Create database if it doesn't exist
-- Run this as a superuser
CREATE DATABASE file_hash_db;

-- Connect to the database
\c file_hash_db

-- Create the file_hashes table
CREATE TABLE IF NOT EXISTS file_hashes (
    id SERIAL PRIMARY KEY,
    file_hash VARCHAR(128) NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_path VARCHAR(1024) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create an index on the file_hash column
CREATE INDEX IF NOT EXISTS file_hash_idx ON file_hashes (file_hash);

-- Create a unique constraint to prevent duplicate entries
ALTER TABLE file_hashes ADD CONSTRAINT unique_hash_path UNIQUE (file_hash, file_path);

-- Create a user with appropriate permissions (optional)
-- CREATE USER file_hash_user WITH PASSWORD 'your_password';
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO file_hash_user;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO file_hash_user; 