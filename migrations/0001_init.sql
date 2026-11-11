-- Distanplay schema, v1.
--
-- Conventions: snake_case, uuid v7 primary keys (time-ordered: good index locality and
-- "newest first" for free), timestamptz everywhere, secrets stored only as SHA-256
-- hashes (bytea), soft deletes where history matters. Every table that's edited has
-- updated_at maintained by a trigger.

CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_bytes() for the uuidv7 fallback

-- uuidv7() is built into PostgreSQL 18. On older servers (Railway may run 16/17)
-- define a compatible one: 48-bit Unix-ms timestamp, version 7, variant 10, random rest.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'uuidv7') THEN
        CREATE FUNCTION uuidv7() RETURNS uuid
        LANGUAGE plpgsql VOLATILE AS $f$
        DECLARE
            ts_ms bigint := floor(extract(epoch FROM clock_timestamp()) * 1000);
            bytes bytea := decode(lpad(to_hex(ts_ms), 12, '0'), 'hex') || gen_random_bytes(10);
        BEGIN
            bytes := set_byte(bytes, 6, (get_byte(bytes, 6) & 15) | 112);  -- version 7
            bytes := set_byte(bytes, 8, (get_byte(bytes, 8) & 63) | 128);  -- variant 10
            RETURN encode(bytes, 'hex')::uuid;
        END
        $f$;
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END
$$;

-- ───────────────────────────── enums ─────────────────────────────

CREATE TYPE user_status AS ENUM ('active', 'suspended', 'deleted');
-- External sign-in providers. Discord today; the rest are ready for later.
CREATE TYPE identity_provider AS ENUM ('discord', 'google', 'apple', 'microsoft', 'github', 'steam');
-- How a session was started (for the sessions list and audits).
CREATE TYPE auth_method AS ENUM ('discord', 'google', 'apple', 'microsoft', 'github', 'steam', 'password', 'passkey');
CREATE TYPE login_request_status AS ENUM ('pending', 'completed', 'consumed', 'failed', 'expired');
CREATE TYPE device_platform AS ENUM ('windows', 'macos', 'linux', 'android', 'ios', 'web', 'other');
CREATE TYPE friendship_status AS ENUM ('pending', 'accepted');
CREATE TYPE connection_request_status AS ENUM ('pending', 'approved', 'auto_approved', 'denied', 'expired', 'canceled');
-- How the media actually flowed: same LAN, direct (port open), NAT hole-punched, or relayed.
CREATE TYPE connection_route AS ENUM ('lan', 'direct', 'punched', 'relay_tcp', 'relay_udp', 'unknown');
CREATE TYPE permission_effect AS ENUM ('allow', 'deny');

-- ───────────────────────────── users & identity ─────────────────────────────

CREATE TABLE users (
    id                uuid PRIMARY KEY DEFAULT uuidv7(),
    -- Discord-style handle: unique, lowercase, 2–32 of a-z 0-9 _ . (no "..").
    username          citext NOT NULL,
    -- Profile name shown to friends (any characters).
    display_name      varchar(32) NOT NULL,
    email             citext,
    email_verified_at timestamptz,
    avatar_url        text,
    status            user_status NOT NULL DEFAULT 'active',
    status_reason     text,
    last_login_at     timestamptz,
    last_seen_at      timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    deleted_at        timestamptz,
    CONSTRAINT users_username_format CHECK (username ~ '^[a-z0-9_.]{2,32}$' AND username !~ '\.\.'),
    CONSTRAINT users_display_name_len CHECK (char_length(display_name) BETWEEN 1 AND 32)
);
CREATE UNIQUE INDEX users_username_key ON users (username);
CREATE UNIQUE INDEX users_email_key ON users (email) WHERE email IS NOT NULL AND deleted_at IS NULL;
CREATE TRIGGER users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- One row per external account linked to a user (Discord now; Google, Apple… later).
CREATE TABLE user_identities (
    id                uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id           uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider          identity_provider NOT NULL,
    provider_user_id  varchar(255) NOT NULL,
    provider_username varchar(255),
    email             citext,
    email_verified    boolean NOT NULL DEFAULT false,
    avatar_url        text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    last_used_at      timestamptz
);
CREATE UNIQUE INDEX user_identities_provider_subject_key ON user_identities (provider, provider_user_id);
CREATE INDEX user_identities_user_idx ON user_identities (user_id);
CREATE TRIGGER user_identities_updated_at BEFORE UPDATE ON user_identities FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Ready for email + password sign-in (argon2id hashes).
CREATE TABLE user_passwords (
    user_id       uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    password_hash varchar(255) NOT NULL,
    must_reset    boolean NOT NULL DEFAULT false,
    changed_at    timestamptz NOT NULL DEFAULT now()
);

-- Ready for passkeys (WebAuthn).
CREATE TABLE user_passkeys (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id bytea NOT NULL,
    public_key    bytea NOT NULL,
    sign_count    bigint NOT NULL DEFAULT 0,
    transports    text[],
    backed_up     boolean NOT NULL DEFAULT false,
    name          varchar(100),
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);
CREATE UNIQUE INDEX user_passkeys_credential_key ON user_passkeys (credential_id);
CREATE INDEX user_passkeys_user_idx ON user_passkeys (user_id);

-- One-time tokens for email flows (verification, password reset, email change).
CREATE TYPE email_token_purpose AS ENUM ('verify_email', 'reset_password', 'change_email');
CREATE TABLE email_tokens (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose    email_token_purpose NOT NULL,
    token_hash bytea NOT NULL,
    new_email  citext,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX email_tokens_hash_key ON email_tokens (token_hash);
CREATE INDEX email_tokens_user_idx ON email_tokens (user_id, purpose);

-- ───────────────────────────── devices & sessions ─────────────────────────────

-- A Distanplay install signed in to an account. Friends connect to devices.
CREATE TABLE devices (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Random id the app generates once per install (survives sign-out/in).
    install_id  uuid NOT NULL,
    name        varchar(64) NOT NULL,
    platform    device_platform NOT NULL DEFAULT 'other',
    os_version  varchar(64),
    app_version varchar(32),
    last_seen_at timestamptz,
    last_ip     inet,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz
);
CREATE UNIQUE INDEX devices_user_install_key ON devices (user_id, install_id);
CREATE INDEX devices_user_idx ON devices (user_id) WHERE revoked_at IS NULL;
CREATE TRIGGER devices_updated_at BEFORE UPDATE ON devices FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Refresh tokens. Each refresh rotates: the used row is marked rotated and a new row
-- joins the same family. Presenting an already-rotated token means it was stolen
-- (or replayed), so the whole family is revoked (OAuth 2.0 BCP §4.14).
CREATE TABLE auth_sessions (
    id                 uuid PRIMARY KEY DEFAULT uuidv7(),
    family_id          uuid NOT NULL,
    user_id            uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id          uuid REFERENCES devices (id) ON DELETE CASCADE,
    refresh_token_hash bytea NOT NULL,
    auth_method        auth_method NOT NULL,
    ip                 inet,
    user_agent         text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    last_used_at       timestamptz NOT NULL DEFAULT now(),
    -- Sliding expiry (extended on each refresh).
    expires_at         timestamptz NOT NULL,
    rotated_at         timestamptz,
    replaced_by        uuid,
    revoked_at         timestamptz,
    revoke_reason      varchar(64)
);
CREATE UNIQUE INDEX auth_sessions_token_key ON auth_sessions (refresh_token_hash);
CREATE INDEX auth_sessions_family_idx ON auth_sessions (family_id);
CREATE INDEX auth_sessions_user_active_idx ON auth_sessions (user_id) WHERE revoked_at IS NULL AND rotated_at IS NULL;

-- Desktop sign-in in progress: the app opens the browser, the provider redirects to
-- the server, and the app polls with a secret only it knows.
CREATE TABLE login_requests (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    provider         identity_provider NOT NULL,
    state_hash       bytea NOT NULL,
    poll_secret_hash bytea NOT NULL,
    install_id       uuid NOT NULL,
    device_name      varchar(64) NOT NULL,
    platform         device_platform NOT NULL DEFAULT 'other',
    os_version       varchar(64),
    app_version      varchar(32),
    status           login_request_status NOT NULL DEFAULT 'pending',
    user_id          uuid REFERENCES users (id) ON DELETE CASCADE,
    error            text,
    ip               inet,
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    completed_at     timestamptz
);
CREATE UNIQUE INDEX login_requests_state_key ON login_requests (state_hash);
CREATE INDEX login_requests_expiry_idx ON login_requests (expires_at) WHERE status IN ('pending', 'completed');

-- ───────────────────────────── friends ─────────────────────────────

-- One row per pair. Pending = requester asked; accepted = friends.
CREATE TABLE friendships (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    requester_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    addressee_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    status       friendship_status NOT NULL DEFAULT 'pending',
    created_at   timestamptz NOT NULL DEFAULT now(),
    responded_at timestamptz,
    CONSTRAINT friendships_not_self CHECK (requester_id <> addressee_id)
);
-- At most one row per unordered pair.
CREATE UNIQUE INDEX friendships_pair_key ON friendships (LEAST(requester_id, addressee_id), GREATEST(requester_id, addressee_id));
CREATE INDEX friendships_addressee_idx ON friendships (addressee_id, status);
CREATE INDEX friendships_requester_idx ON friendships (requester_id, status);

CREATE TABLE user_blocks (
    blocker_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    blocked_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (blocker_id, blocked_id),
    CONSTRAINT user_blocks_not_self CHECK (blocker_id <> blocked_id)
);

-- What `owner` lets `friend` do on the owner's devices. Missing row = defaults
-- (ask every time, input allowed, audio allowed, no clipboard).
CREATE TABLE friend_permissions (
    owner_id                     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    friend_id                    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    connect_without_approval     boolean NOT NULL DEFAULT false,
    control_input                boolean NOT NULL DEFAULT true,
    hear_audio                   boolean NOT NULL DEFAULT true,
    use_clipboard                boolean NOT NULL DEFAULT false,
    transfer_files               boolean NOT NULL DEFAULT false,
    created_at                   timestamptz NOT NULL DEFAULT now(),
    updated_at                   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (owner_id, friend_id),
    CONSTRAINT friend_permissions_not_self CHECK (owner_id <> friend_id)
);
CREATE TRIGGER friend_permissions_updated_at BEFORE UPDATE ON friend_permissions FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ───────────────────────────── connections ─────────────────────────────

-- A viewer asking to connect to a device (approved automatically when the owner
-- allows that friend to connect without approval).
CREATE TABLE connection_requests (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    viewer_user_id   uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    viewer_device_id uuid REFERENCES devices (id) ON DELETE SET NULL,
    host_user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    host_device_id   uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    status           connection_request_status NOT NULL DEFAULT 'pending',
    created_at       timestamptz NOT NULL DEFAULT now(),
    responded_at     timestamptz,
    expires_at       timestamptz NOT NULL
);
CREATE INDEX connection_requests_host_pending_idx ON connection_requests (host_device_id) WHERE status = 'pending';
CREATE INDEX connection_requests_viewer_idx ON connection_requests (viewer_user_id, created_at DESC);

-- What actually happened: one row per stream, for history, support and stats.
CREATE TABLE connection_sessions (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    request_id       uuid REFERENCES connection_requests (id) ON DELETE SET NULL,
    viewer_user_id   uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    viewer_device_id uuid REFERENCES devices (id) ON DELETE SET NULL,
    host_user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    host_device_id   uuid REFERENCES devices (id) ON DELETE SET NULL,
    route            connection_route NOT NULL DEFAULT 'unknown',
    started_at       timestamptz NOT NULL DEFAULT now(),
    ended_at         timestamptz,
    end_reason       varchar(64),
    bytes_relayed    bigint NOT NULL DEFAULT 0
);
CREATE INDEX connection_sessions_viewer_idx ON connection_sessions (viewer_user_id, started_at DESC);
CREATE INDEX connection_sessions_host_idx ON connection_sessions (host_user_id, started_at DESC);

-- ───────────────────────────── library: recents & favorites ─────────────────────────────

-- A target is either a friend's device or a raw address/code (hosts without accounts).
CREATE TABLE recent_connections (
    id                uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id           uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    target_device_id  uuid REFERENCES devices (id) ON DELETE CASCADE,
    target_address    varchar(255),
    label             varchar(64) NOT NULL,
    connect_count     integer NOT NULL DEFAULT 1,
    last_connected_at timestamptz NOT NULL DEFAULT now(),
    created_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT recent_connections_one_target CHECK ((target_device_id IS NULL) <> (target_address IS NULL))
);
CREATE UNIQUE INDEX recent_connections_device_key ON recent_connections (user_id, target_device_id) WHERE target_device_id IS NOT NULL;
CREATE UNIQUE INDEX recent_connections_address_key ON recent_connections (user_id, target_address) WHERE target_address IS NOT NULL;
CREATE INDEX recent_connections_user_idx ON recent_connections (user_id, last_connected_at DESC);

CREATE TABLE favorites (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id          uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    target_device_id uuid REFERENCES devices (id) ON DELETE CASCADE,
    target_address   varchar(255),
    label            varchar(64) NOT NULL,
    position         integer NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT favorites_one_target CHECK ((target_device_id IS NULL) <> (target_address IS NULL))
);
CREATE UNIQUE INDEX favorites_device_key ON favorites (user_id, target_device_id) WHERE target_device_id IS NOT NULL;
CREATE UNIQUE INDEX favorites_address_key ON favorites (user_id, target_address) WHERE target_address IS NOT NULL;
CREATE INDEX favorites_user_idx ON favorites (user_id, position);

-- ───────────────────────────── roles & permissions (admin) ─────────────────────────────

CREATE TABLE roles (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    key         varchar(64) NOT NULL,
    name        varchar(100) NOT NULL,
    description varchar(255),
    -- System roles can't be deleted from the admin app.
    is_system   boolean NOT NULL DEFAULT false,
    -- Given to every new user.
    is_default  boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX roles_key_key ON roles (key);
CREATE TRIGGER roles_updated_at BEFORE UPDATE ON roles FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Permission keys are "resource.action", e.g. "users.suspend".
CREATE TABLE permissions (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    key         varchar(100) NOT NULL,
    resource    varchar(50) NOT NULL,
    action      varchar(50) NOT NULL,
    description varchar(255),
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX permissions_key_key ON permissions (key);

CREATE TABLE role_permissions (
    role_id       uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id    uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    granted_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX user_roles_role_idx ON user_roles (role_id);

-- Per-user exceptions on top of roles (deny wins).
CREATE TABLE user_permissions (
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    effect        permission_effect NOT NULL DEFAULT 'allow',
    granted_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, permission_id)
);

-- ───────────────────────────── audit ─────────────────────────────

CREATE TABLE audit_log (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_user_id uuid REFERENCES users (id) ON DELETE SET NULL,
    action        varchar(64) NOT NULL,
    target_type   varchar(32),
    target_id     uuid,
    ip            inet,
    user_agent    text,
    metadata      jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_actor_idx ON audit_log (actor_user_id, created_at DESC);
CREATE INDEX audit_log_target_idx ON audit_log (target_type, target_id, created_at DESC);
CREATE INDEX audit_log_action_idx ON audit_log (action, created_at DESC);
