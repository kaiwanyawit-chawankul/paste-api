-- Add is_encrypted column with a default value of false
ALTER TABLE pastes
ADD COLUMN IF NOT EXISTS is_encrypted BOOLEAN DEFAULT false;
