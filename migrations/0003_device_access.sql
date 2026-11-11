-- Connection codes: every device gets a random 9-digit code and a password, made by the
-- server, so anyone with both can reach it from anywhere (the server finds the device
-- and sets up the peer-to-peer connection). The password is stored only as an argon2id
-- hash; the app keeps its own copy to show it.
CREATE TABLE device_access (
    device_id       uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code            char(9) NOT NULL,
    password_hash   text NOT NULL,
    -- Set by the user ("set my own") rather than generated.
    custom_password boolean NOT NULL DEFAULT false,
    failed_attempts integer NOT NULL DEFAULT 0,
    locked_until    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT device_access_code_digits CHECK (code ~ '^[0-9]{9}$')
);
CREATE UNIQUE INDEX device_access_code_key ON device_access (code);
CREATE INDEX device_access_user_idx ON device_access (user_id);
CREATE TRIGGER device_access_updated_at BEFORE UPDATE ON device_access FOR EACH ROW EXECUTE FUNCTION set_updated_at();
