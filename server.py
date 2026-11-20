# What goes to the "server"
# Essentially stores transmitted data, but never can see it 
# Data should be encrypted in transmission 

# Server handles the implementation of each role's permissions 
#    * When a user calls a function e.g. get token, the server must validate their role and subsequent permissions 
#        and then enact or deny that request 
#    * The server cant see the messages and must call the audit log for each enacted request
#    * Intermediary and implementation of all the files 

import passwords, rbac, store, audit, tokens
import crypto_utils as cu 
# -----------------------------------
# HELPERS/SET UP

# get the policy: e.g. metainfo about whisperchain: what round, etc. 
def get_policy(conn, key):
    return conn.execute("SELECT value FROM policy WHERE key = ?", (key,)).fetchone()["value"]

# get the roles of a user  
def roles_of(user):
    return user["roles"].split(",")

# check if the user has a role with the permission 
def check_perm(conn, user, perm):
    if not rbac.has_permission(roles_of(user), perm): # check if any of the user's roles have the permission
        audit.log(conn, "access_denied:" + perm.value, user["roles"]) # log the attempt
        conn.commit()
        raise PermissionError("permission denied")
    return True # return true that they do have permission 

# first connect to the database to use while server is running
def load_app():
    conn = store.connect()
    return conn

# -----------------------------------
# LOGIN/AUTH

# handles a singular login attempt
def authenticate_login(conn, username, pswd):
     # load the row keyed by this username
    user = conn.execute("SELECT * FROM users WHERE username = ? AND active = 1",(username,)).fetchone()

    # if the user is not registered, return none
    if user is None:
        return None

    # if the user is registered, check that the password is correct
    if passwords.check_password(pswd, user["pw_hash"]) is False:
        return None
    return user

# get a user's information from the database
def get_user(conn, user_id):
    return conn.execute("SELECT * FROM users WHERE id = ? AND active = 1",(user_id,)).fetchone()

# -----------------------------------
# Now set up functionality for each role 
# -----------------------------------
# ADMIN 

# create a user
def create_user(conn, admin, username, pswd):
    # check that the user who claimed to be admin is actually admin/a user with this permission
    check_perm(conn, admin, rbac.Permissions.CREATE_USER)

    # now set up the user/pswd pair 
    hashed = passwords.hash_password(pswd)

    # write the username and hashed password into the db 
    conn.execute("INSERT INTO users (username, pw_hash, roles) VALUES (?, ?, ?)", (username, hashed, "sender"))

    # log that this user was created
    audit.log(conn, "user_created", "admin")
    conn.commit() # commit the changes to db

# assign a role/roles to the user 
def assign_role(conn, admin, username, role):
    # check that the admin is valid 
    check_perm(conn, admin, rbac.Permissions.ASSIGN_ROLE)

    # find the registered user 
    user = conn.execute("SELECT roles FROM users WHERE username = ?", (username,)).fetchone()

    # check validity 
    if user is None:
        raise ValueError("user does not exist")

    # allow for multiple roles: every user should be a sender and recipient 
    if isinstance(role, str):
        requested_roles = role.split(",")
    else:
        requested_roles = role

    # generate a list of validated roles
    new_roles = set()
    for r in requested_roles: # loop over each requested role, and validate whether this role is valid 
        try:
            new_roles.add(rbac.Role(r.strip()).value) # ensure cleanliness 
        except (ValueError, AttributeError):
            raise ValueError("invalid role: " + str(r))

    # if the user has existing roles, keep them
    existing_roles = set(user["roles"].split(","))
    all_roles = existing_roles.union(new_roles) # just add in the new roles
    roles_string = ",".join(sorted(all_roles)) # conver to string for writing to db 

    # put the new list of roles in 
    conn.execute("UPDATE users SET roles = ? WHERE username = ?", (roles_string, username))

    # log and commit changes 
    audit.log(conn, "assign_role", "admin")
    conn.commit()

# admin can view the logs: also implements admin ability to view meta events 
def view_log(conn, admin):
    # confirm
    check_perm(conn, admin, rbac.Permissions.VIEW_LOG)

    # grab the whole log
    whole_log = conn.execute("SELECT seq, t, action, role, prev_hash, entry_hash FROM audit_log ORDER BY seq").fetchall()

    # log that someone accessed the log
    audit.log(conn, "viewed_audit_log", "admin")
    conn.commit() # commit the changes
    return whole_log

# admin can change the policies enacted, e.g. up the flag threshold to 5 so that after 5 flags, there is an alert to the mod
def rotate_policy(conn, admin, key, value):
    # check that the user is an admin
    check_perm(conn, admin, rbac.Permissions.ROTATE_POLICY)

    # Only allow recognized policy settings
    allowed = ["round", "flag_threshold"]

    if key not in allowed:
        raise ValueError("invalid policy setting")

    # Make sure the new value is valid
    if not isinstance(value, int) or value < 1:
        raise ValueError("Policy value must be a positive integer")

    # update the policy
    conn.execute("UPDATE policy SET value = ? WHERE key = ?", (value, key))

    # record and commit changes
    audit.log(conn, "policy_changed:" + key, "admin")
    conn.commit()

# register a key for the users, clients will generate their own key pair and give the public to the server
def register_key(conn, admin, username, public_pem):
    # check that the admin is legit
    check_perm(conn, admin, rbac.Permissions.REGISTER_KEY)

    # find the user assocaited
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        raise ValueError("user does not exist")

    # load the public key from pem 
    cu.load_public(public_pem)
    
    # upload the public key into the db  
    conn.execute("UPDATE users SET public_key = ? WHERE username = ?", (public_pem, username))

    # log and commit changes
    audit.log(conn, "key_registered", "admin")
    conn.commit()

# revoke a key from a sender
def revoke_key(conn, admin,  username):
    # check that this admin is legit 
    check_perm(conn, admin, rbac.Permissions.REVOKE_KEY)

    # grab the user 
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        
    # check that the user exists
    if user is None:
        raise ValueError("user does not exist")

    # if this user has no key, then it cannot be revoked
    if user["public_key"] is None:
        raise ValueError("user has no registered public key")

    # if the key is there, set it to null
    conn.execute("UPDATE users SET public_key = NULL WHERE id = ?",(user["id"],))
    audit.log(conn, "public_key_revoked", "admin")
    conn.commit()
    
# -----------------------------------
# SENDER 

# tokens logic 
def issue_token(conn, user):
    # check that the user is a sender
    check_perm(conn, user, rbac.Permissions.GET_TOKEN)

    # get the round
    round_id = get_policy(conn, "round")

    # now with the round, we can see if this sender has received a token already 
    has_token = conn.execute("SELECT 1 FROM issuance WHERE user_id = ? AND round_id = ?", (user["id"], round_id)).fetchone()
    if has_token:
        raise ValueError("you already received a token this round")

    # now that the user is validated and since it has not received a token for the round, generate one
    token = tokens.generate_token()
    token_hash = tokens.hash_token(token)

    # record that this user has received a token
    conn.execute("INSERT INTO issuance (user_id, round_id) VALUES (?, ?)",(user["id"], round_id))

    # store the token hash separately so the server can verify it later
    conn.execute("INSERT INTO issued_tokens (round_id, token_hash) VALUES (?, ?)", (round_id, token_hash))
    audit.log(conn, "token_issued", "sender")
    conn.commit()
    return token # for use

def view_recipients(conn, sender):
    # check that the user is a sender
    check_perm(conn, sender, rbac.Permissions.VIEW_RECIPIENTS)

    # send a list of active users 
    rows = conn.execute("SELECT username, roles FROM users WHERE active = 1 AND public_key IS NOT NULL ORDER BY username").fetchall()

    # get their usernames
    usernames = []
    for r in rows:
        if "recipient" in r["roles"].split(","):
            usernames.append(r["username"])
    audit.log(conn, "viewed_recipients", "sender") # log that the sender viewed the recipients
    conn.commit()
    return usernames

# senders need to get the recipient's key for encryption
def get_recipient_key(conn, sender, username):
    check_perm(conn, sender, rbac.Permissions.GET_RECIPIENT_KEY)

    # get the recipient
    recipient = conn.execute("SELECT public_key FROM users WHERE username = ? AND active = 1", (username,)).fetchone()
    if recipient is None or recipient["public_key"] is None:
        raise ValueError("recipient not found or has no registered public key")

    return recipient["public_key"] # return the public key to the sender 

# if a user has requested that a message be sent, server must verify this and send it over 
def submit_message(conn, user, recipient, token, encrypted_msg, wrapped_key, nonce):
    # submitting a message to the recipient requires a token from the sender, the symmetric key used to encrypt the message along side the nonce so the 
    # recipient can decrypt, and the encrypted message itself 

    # only senders can submit messages
    check_perm(conn, user, rbac.Permissions.SEND_MESSAGE)
    round_id = get_policy(conn, "round") # get the round to check the if the token has been issued 
    token_hash = tokens.hash_token(token)

    # Check that the token was actually issued
    issued = conn.execute("SELECT frozen, used FROM issued_tokens WHERE round_id = ? AND token_hash = ?", (round_id, token_hash)).fetchone()

    # check if the token is issued, frozen, or used before going to submit a message
    if issued is None:
        raise ValueError("invalid token")
    if issued["frozen"]:
        raise ValueError("this token has been frozen")
    if issued["used"]:
        raise ValueError("this token has already been used")

    # get the recipient
    recipient = conn.execute("SELECT id FROM users WHERE username = ? AND active = 1", (recipient,)).fetchone()
    if recipient is None: # check that this is a valid recipient 
        raise ValueError("recipient not found")

    # store the encrypted message without recording the sender
    cursor = conn.execute("INSERT INTO messages (recipient_id, round_id, ciphertext, wrapped_key, nonce, token_hash) VALUES (?, ?, ?, ?, ?, ?)",
        (recipient["id"], round_id, encrypted_msg, wrapped_key, nonce, token_hash))
    message_id = cursor.lastrowid # helpful for identifying messages that are flagged; gives ID

    # mark the token as used
    conn.execute("UPDATE issued_tokens SET used = 1 WHERE round_id = ? AND token_hash = ?",
        (round_id, token_hash)
    )
    audit.log(conn, "message_sent", "sender")
    conn.commit()
    return message_id

# -----------------------------------
# RECIPIENT

# recipient should be able to receive the messages addressed to them 
def read_messages(conn, recipient):
    # check permissons
    check_perm(conn, recipient, rbac.Permissions.READ_MESSAGES)

    # get the messages indexed to the recipient's ID
    messages = conn.execute("SELECT id, round_id, ciphertext, wrapped_key, nonce FROM messages WHERE recipient_id = ? ORDER BY id",
        (recipient["id"],)).fetchall()

    # log that they got their messages 
    audit.log(conn, "messages_retrieved", "recipient")
    conn.commit()
    return messages # returns the encrypted components so the user can use their local priv key to decrypt them 

# if a recipient wants to flag the message, they need to encrypt the message with the mod's key so that the moderator can see it 
def get_mod_key(conn, recipient):
    # check permissons
    check_perm(conn, recipient, rbac.Permissions.GET_MOD_KEY)

    # grab the active users with registered public keys
    rows = conn.execute("SELECT roles, public_key FROM users WHERE active = 1 AND public_key IS NOT NULL").fetchall()

    # loop over all the active users and generate a list of moderators with keys and keep track of those without
    with_key = []
    for r in rows:
        if "moderator" in r["roles"].split(","):
            if r["public_key"] is not None:
                with_key.append(r["public_key"])
            else:
                without_key += 1

    # if the list is empty 
    if not with_key:
        if without_key: # but we have an existing moderator with a key
            raise ValueError("a moderator exists but has not registered a key yet")
        raise ValueError("no moderator account exists")

    return with_key[0]


# recipient should be able to flag inappropriate messages 
def flag_message(conn, recipient, message_id, reason, mod_cipher, mod_wrapped_key, mod_nonce):
    # checks that the role is valid 
    check_perm(conn, recipient, rbac.Permissions.FLAG_MESSAGE)

    # must provide a reason
    if not reason or not reason.strip():
        raise ValueError("A reason is required in order to flag a message")

    # find the message according to the id and the recipients "inbox"
    message = conn.execute("SELECT * FROM messages WHERE id = ? AND recipient_id = ?", (message_id, recipient["id"])).fetchone()

    # if the message is flagged or does not exist, do not proceed
    if message is None: 
        raise ValueError("message not found")
    if message["flagged"]:
        raise ValueError("message has already been flagged")

    # set the message as flagged if it exists
    conn.execute("UPDATE messages SET flagged = 1 WHERE id = ?", (message_id,))

    # now, drop the message into moderator queue and store the essential information for the moderator in order to decrypt it
    conn.execute("""INSERT INTO flags(message_id, reason, mod_copy, mod_wrapped_key, mod_nonce)
        VALUES (?, ?, ?, ?, ?)""", (message_id, reason, mod_cipher, mod_wrapped_key, mod_nonce)) # mod wrapped key is the symmetric key used for encryption but hybrid encrypted under mod pub

    audit.log(conn, "flag_message", "recipient") # log the flag

    # check if the amount of flags opened exceeds the specified threshold
    curr_opened_count = conn.execute("SELECT COUNT(*) FROM flags WHERE status = 'open'").fetchone()[0]
    if curr_opened_count >= get_policy(conn, "flag_threshold"):
        audit.log(conn, "flag_threshold_reached", "system") # notify 
   
    conn.commit()

# -------------------------------------------------------------------------------
# MODERATOR

# moderator's permissions police and control message sending 
# first, they can view what messages have been flagged 
def view_flagged(conn, moderator):
    # check permission 
    check_perm(conn, moderator, rbac.Permissions.VIEW_FLAGGED)

    # open the db and return the flags table which stores message_id, reason, and the encrypted copy of the message for the mod 
    flags = conn.execute("""SELECT f.id, f.message_id, f.reason, f.mod_copy, f.mod_wrapped_key, f.mod_nonce, f.status
        FROM flags f ORDER BY f.id""").fetchall()

    # log that the mod viewed messages 
    audit.log(conn, "viewed_flagged_messages", "moderator")
    conn.commit()
    return flags

# after viewing the messages, they can resolve the flags and then also freeze tokens 
def resolve_flag(conn, moderator, flag_id):
    # check mod
    check_perm(conn, moderator, rbac.Permissions.RESOLVE_FLAG)

    # find the flag
    flag = conn.execute("SELECT * FROM flags WHERE id = ?", (flag_id,)).fetchone()

    # if it is not there or already resolved, don't resolve it
    if flag is None:
        raise ValueError("flag not found")
    if flag["status"] == "resolved":
        raise ValueError("flag has already been resolved")

    # otherwise mark the flag as resolved
    conn.execute("UPDATE flags SET status = 'resolved' WHERE id = ?", (flag_id,))
    audit.log(conn, "flag_resolved", "moderator")
    conn.commit()

# with a flag id, the mod can get the message id, then find the message; all void of knowing the sender
# they get flag/message id from view_flags
def freeze_token(conn, moderator, message_id):
    # check mod
    check_perm(conn, moderator, rbac.Permissions.FREEZE_TOKEN)

    # find the message associated with ID
    message = conn.execute("SELECT round_id, token_hash, flagged FROM messages WHERE id = ?", (message_id,)).fetchone()

    # note if the message is not found or flagged
    if message is None:
        raise ValueError("message not found")
    if not message["flagged"]:
            raise ValueError("message has not been flagged, cannot freeze token")

    # try to mark the token as frozen
    try:
        result = conn.execute("UPDATE issued_tokens SET frozen = 1 WHERE round_id = ? AND token_hash = ?", (message["round_id"], message["token_hash"]))

        # if there was not a row returned --> no token found
        if result.rowcount != 1:
            raise ValueError("token not found")

        audit.log(conn, "token_frozen", "moderator")
        conn.commit()

    # if for whatever reason something fails, undo the changes and return
    except Exception:
        conn.rollback()
        raise
    
