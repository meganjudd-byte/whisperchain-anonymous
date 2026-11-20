# The "user's device" side: key generation, encrypting, decrypting, holding tokens.
# Private keys and plaintext messages only ever exist in this file's functions.
# Everything handed to server.py is ciphertext, a public key, or a token.

import os, re
import crypto_utils as cu
import server, store

MAX_CHARS = 500


# PATH HELPERS

# usernames end up in file names, so only allow safe characters (blocks "../x")
def _check_name(username):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", username or ""):
        raise ValueError("usernames may only contain letters, digits, _ and -")
    return username

def _private_path(username):
    return os.path.join(store.keys_dir(), _check_name(username) + "_private.pem")

def _public_path(username):
    return os.path.join(store.keys_dir(), _check_name(username) + "_public.pem")

def tokens_dir():
    return os.path.join(store.DATA_DIR, "tokens")


# LOGIN

# returns the user row that every other function needs
def login(conn, username, pswd):
    user = server.authenticate_login(conn, username, pswd)
    if user is None:
        raise PermissionError("Invalid username or password")
    return user


# KEYS (every role)

# every user makes their own key pair; the private key never leaves this device
def keygen(username, key_passphrase):
    if os.path.exists(_private_path(username)):
        # overwriting would make every message already sent to this user unreadable
        raise FileExistsError("a key already exists for " + username)

    key = cu.generate_keypair()
    os.makedirs(store.keys_dir(), exist_ok=True)

    with open(_private_path(username), "wb") as f:
        f.write(cu.private_to_pem(key, key_passphrase))  # encrypted with the passphrase
    os.chmod(_private_path(username), 0o600)

    # public half is written out so the admin can register it
    with open(_public_path(username), "w") as f:
        f.write(cu.public_to_pem(key))
    return _public_path(username)

def load_private(username, key_passphrase):
    with open(_private_path(username), "rb") as f:
        return cu.load_private(f.read(), key_passphrase)


# ADMIN (the admin only ever handles public keys and metadata)

def create_user(conn, admin, username, password):
    _check_name(username)
    server.create_user(conn, admin, username, password)

def assign_role(conn, admin, username, role):
    server.assign_role(conn, admin, username, role)

# registers the public key the user generated with keygen()
def register_key(conn, admin, username):
    with open(_public_path(username)) as f:
        server.register_key(conn, admin, username, f.read())

def revoke_key(conn, admin, username):
    server.revoke_key(conn, admin, username)

def change_policy(conn, admin, key, value):
    server.rotate_policy(conn, admin, key, value)

# admin and moderator both get the role-level audit log (no content, no identities)
def view_log(conn, user):
    return server.view_log(conn, user)


# SENDER

def list_recipients(conn, sender):
    return server.view_recipients(conn, sender)

# ask for this round's token and keep it on this device
def get_token(conn, sender):
    token = server.issue_token(conn, sender)   # raises if already issued this round
    round_id = server.get_policy(conn, "round")

    os.makedirs(tokens_dir(), exist_ok=True)
    path = os.path.join(tokens_dir(), "%s_round%d.token" % (sender["username"], round_id))
    with open(path, "w") as f:
        f.write(token.hex())
    os.chmod(path, 0o600)
    return path

# encrypt for the recipient here, then submit with the token
def send_message(conn, sender, token_path, to_username, text):
    if not text or len(text) > MAX_CHARS:
        raise ValueError("message must be 1-%d characters" % MAX_CHARS)

    with open(token_path) as f:
        token = bytes.fromhex(f.read().strip())

    public_pem = server.get_recipient_key(conn, sender, to_username)
    ciphertext, wrapped_key, nonce = cu.encrypt(public_pem, text)  # server never sees plaintext
    message_id = server.submit_message(conn, sender, to_username, token, ciphertext, wrapped_key, nonce)

    # the token is spent, so mark the local file too
    os.replace(token_path, token_path + ".used")
    return message_id


# RECIPIENT

# fetch and decrypt everything in this user's inbox
def read_inbox(conn, user, key_passphrase):
    key = load_private(user["username"], key_passphrase)
    out = []
    for row in server.read_messages(conn, user):
        try:
            text = cu.decrypt(key, row["ciphertext"], row["wrapped_key"], row["nonce"])
        except Exception:
            # a sender can submit garbage the server can't validate; don't lose the whole inbox
            text = "(could not decrypt this message)"
        out.append((row["id"], row["round_id"], text))
    return out

# flag a message: re-wrap its AES key for the moderator, so the moderator gets a copy
# without the recipient having to re-encrypt the whole text
def flag(conn, user, key_passphrase, message_id, reason):
    key = load_private(user["username"], key_passphrase)

    rows = [r for r in server.read_messages(conn, user) if r["id"] == message_id]
    if not rows:
        raise ValueError("that message is not in your inbox")
    row = rows[0]

    mod_pem = server.get_mod_key(conn, user)
    mod_wrapped_key = cu.rewrap_key(key, row["wrapped_key"], mod_pem)
    server.flag_message(conn, user, message_id, reason, row["ciphertext"], mod_wrapped_key, row["nonce"])


# MODERATOR

# the flagged queue, each message decrypted with the moderator's private key
def read_queue(conn, mod, key_passphrase):
    key = load_private(mod["username"], key_passphrase)
    out = []
    for row in server.view_flagged(conn, mod):
        try:
            text = cu.decrypt(key, row["mod_copy"], row["mod_wrapped_key"], row["mod_nonce"])
        except Exception:
            text = "(could not decrypt; not encrypted for your key)"
        out.append((row["id"], row["message_id"], row["reason"], row["status"], text))
    return out

def resolve_flag(conn, mod, flag_id):
    server.resolve_flag(conn, mod, flag_id)

# freezes the anonymous token behind a flagged message (moderator never learns who sent it)
def freeze_token(conn, mod, message_id):
    server.freeze_token(conn, mod, message_id)
