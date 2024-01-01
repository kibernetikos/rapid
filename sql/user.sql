CREATE TABLE user (
    id TEXT PRIMARY KEY,             -- Unique identifier for the user
    username TEXT UNIQUE NOT NULL,   -- Username of the user
    password TEXT NOT NULL,          -- Hashed password
    created_at INTEGER NOT NULL      -- Timestamp for user creation
);
