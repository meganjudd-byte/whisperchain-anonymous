# Store the user information in SQLite database 

import sqlite3, os

DATA_DIR = os.environ.get("WC_DATA", "data")  # tests and the demo point this somewhere else


def db_path():
    return os.path.join(DATA_DIR, "whisperchain.db")  # the path to the database file


def keys_dir():
    return os.path.join(DATA_DIR, "keys")  # key files (stand in for each user's own device)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users ( -- first, make a user file
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT NOT NULL UNIQUE,
    pw_hash    TEXT NOT NULL,
    roles      TEXT NOT NULL,            -- comma separated, e.g. 'sender,recipient'
    public_key TEXT,                     -- public half only; private key never reaches the server
    active     INTEGER NOT NULL DEFAULT 1
);

-- records which user got a token
CREATE TABLE IF NOT EXISTS issuance ( 
    user_id INTEGER NOT NULL REFERENCES users(id),
    round_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, round_id)
);

-- records the characteristics of the tokens per round
CREATE TABLE IF NOT EXISTS issued_tokens (
    round_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,
    frozen INTEGER NOT NULL DEFAULT 0,
    used INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (round_id, token_hash)
);

-- no sender column or timestap --> anonymous sending.
CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id INTEGER NOT NULL REFERENCES users(id),
    round_id     INTEGER NOT NULL,
    ciphertext   TEXT NOT NULL,
    wrapped_key  TEXT NOT NULL,
    nonce        TEXT NOT NULL,
    token_hash   TEXT NOT NULL,
    flagged      INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (round_id, token_hash)
        REFERENCES issued_tokens(round_id, token_hash),
    UNIQUE (round_id, token_hash)
);

-- flag table set up for mod use only 
CREATE TABLE IF NOT EXISTS flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL UNIQUE REFERENCES messages(id),
    reason TEXT NOT NULL,
    mod_copy TEXT NOT NULL,          -- encrypted for moderator
    mod_wrapped_key TEXT,             -- AES key encrypted with moderator's RSA key
    mod_nonce TEXT,                   -- AES-GCM nonce
    status TEXT NOT NULL DEFAULT 'open'
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq        INTEGER PRIMARY KEY,
    t         REAL NOT NULL,
    action     TEXT NOT NULL,
    role       TEXT NOT NULL,            -- role only, never a user id
    prev_hash  TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy (
    key   TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);

-- The database itself refuses to edit or delete log rows.
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
"""

# how code talks to the database
def connect(path=None):
    path = path or db_path()
    if path != ":memory:":  # if the folder DNE
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path)  # create and connect the sql database to make changes or view
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)

    columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(flags)")
    }
    if "mod_wrapped_key" not in columns:
        conn.execute("ALTER TABLE flags ADD COLUMN mod_wrapped_key TEXT")
    if "mod_nonce" not in columns:
        conn.execute("ALTER TABLE flags ADD COLUMN mod_nonce TEXT")

    # starting policy (does nothing if the rows are already there)
    for key, value in (("round", 1), ("flag_threshold", 3)):
        conn.execute("INSERT OR IGNORE INTO policy (key, value) VALUES (?, ?)", (key, value))
        
    conn.commit()
    return conn