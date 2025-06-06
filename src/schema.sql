CREATE TABLE pastes (
  id VARCHAR(8) PRIMARY KEY,
  content TEXT NOT NULL,
  language VARCHAR(50),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP WITH TIME ZONE,
  views INTEGER DEFAULT 0,
  burn_after_read BOOLEAN DEFAULT false,
  is_private BOOLEAN DEFAULT false,
  deleted BOOLEAN DEFAULT false
);

CREATE INDEX idx_expires_at ON pastes(expires_at);
CREATE INDEX idx_deleted ON pastes(deleted);