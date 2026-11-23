-- Guests: the app can be used without signing in, for connecting by code, password or
-- link only. A guest is an account with no identity (no Discord), hidden from friend
-- search; it gets the same device code and invites as anyone. Unused guests are
-- removed by the periodic cleanup.
ALTER TABLE users ADD COLUMN is_guest boolean NOT NULL DEFAULT false;
CREATE INDEX users_guest_idx ON users (created_at) WHERE is_guest;
ALTER TYPE auth_method ADD VALUE IF NOT EXISTS 'guest';
