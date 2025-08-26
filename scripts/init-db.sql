-- Initialize the authentication service database

-- Create database if it doesn't exist
SELECT 'CREATE DATABASE auth_service_db'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'auth_service_db')\gexec

-- Connect to the database
\c auth_service_db;

-- Create extensions if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE auth_service_db TO auth_user;