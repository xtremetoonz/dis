CREATE DATABASE dis_database;

USE dis_database;

CREATE TABLE scans (
    id VARCHAR(36) PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    results TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
