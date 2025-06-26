-- Initialization script for GitSearch database

-- Set character set and collation
SET NAMES utf8mb4;
SET CHARACTER SET utf8mb4;

-- Create database if not exists (already created by environment variables)
-- CREATE DATABASE IF NOT EXISTS gitsearch_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Use the database
USE gitsearch_db;

-- Create additional indexes for performance (will be created by Django migrations)
-- These are just examples of what might be useful

-- Indexes for leaks table (will be created by Django)
-- CREATE INDEX idx_leaks_company_level ON leaks_leak(company_id, level);
-- CREATE INDEX idx_leaks_found_at ON leaks_leak(found_at);
-- CREATE INDEX idx_leaks_approval_status ON leaks_leak(approval);

-- Indexes for comments table
-- CREATE INDEX idx_comments_leak_created ON comments_comment(leak_id, created_at);
-- CREATE INDEX idx_comments_author ON comments_comment(author_id);

-- Create a view for leak statistics (example)
-- This will be created after Django migrations
-- CREATE OR REPLACE VIEW leak_stats AS
-- SELECT 
--     c.name as company_name,
--     COUNT(*) as total_leaks,
--     SUM(CASE WHEN l.level = 2 THEN 1 ELSE 0 END) as high_severity,
--     SUM(CASE WHEN l.level = 1 THEN 1 ELSE 0 END) as medium_severity,
--     SUM(CASE WHEN l.level = 0 THEN 1 ELSE 0 END) as low_severity,
--     SUM(CASE WHEN l.approval = 0 THEN 1 ELSE 0 END) as pending,
--     SUM(CASE WHEN l.approval = 1 THEN 1 ELSE 0 END) as approved,
--     SUM(CASE WHEN l.approval = 2 THEN 1 ELSE 0 END) as not_found,
--     SUM(CASE WHEN l.is_false_positive = 1 THEN 1 ELSE 0 END) as false_positives
-- FROM leaks_company c
-- LEFT JOIN leaks_leak l ON c.id = l.company_id
-- GROUP BY c.id, c.name;

-- Grant additional privileges if needed
-- GRANT SELECT, INSERT, UPDATE, DELETE ON gitsearch_db.* TO 'gitsearch_user'@'%';

-- Flush privileges
FLUSH PRIVILEGES;

-- Log initialization
SELECT 'GitSearch database initialization completed' as message;

