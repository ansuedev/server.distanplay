-- Invites: a link (https://<server>/j/<token>) that lets someone join a host's PC.
-- Made by the Discord /jugar command (one per invited friend, or one open invite) and
-- by the app (the "Join" button on the host's Discord profile). Only a SHA-256 of the
-- token is stored.
CREATE TABLE invites (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    token_hash      bytea NOT NULL,
    host_user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    host_device_id  uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    -- Only this Discord account may use it (the host named them, so no approval prompt).
    -- NULL: anyone signed in, and the host approves each one.
    for_discord_id  varchar(32),
    for_name        varchar(100),
    -- 'discord' (/jugar), 'presence' (Discord profile button), 'app'.
    source          varchar(16) NOT NULL,
    max_uses        integer NOT NULL DEFAULT 1,
    uses            integer NOT NULL DEFAULT 0,
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT invites_uses_ok CHECK (uses >= 0 AND max_uses >= 1)
);
CREATE UNIQUE INDEX invites_token_key ON invites (token_hash);
CREATE INDEX invites_host_device_idx ON invites (host_device_id) WHERE revoked_at IS NULL;
