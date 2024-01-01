CREATE TABLE session (
    id TEXT PRIMARY KEY,       -- Unique identifier for the session
    user_id TEXT NOT NULL,     -- Associated user ID
    token TEXT NOT NULL,       -- Token or token identifier
    created_at INTEGER NOT NULL,   -- Timestamp for session creation
    expires_at INTEGER NOT NULL    -- Timestamp for session expiration
);