-- Create database if it doesn't exist
CREATE DATABASE IF NOT EXISTS file_hash_db;

-- Use the database
USE file_hash_db;

-- Create the file_hashes table
CREATE TABLE IF NOT EXISTS file_hashes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    file_hash VARCHAR(128) NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_path VARCHAR(1024) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX (file_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create a user with appropriate permissions (optional)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON file_hash_db.* TO 'file_hash_user'@'localhost' IDENTIFIED BY 'your_password';
-- FLUSH PRIVILEGES; 