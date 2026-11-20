# Command line front end for WhisperChain
# Same idea as the password manager's main.py: log in (with a lockout after too many
# bad attempts), then loop over a menu until the user quits or sits idle too long.
# The difference is that the menu depends on the roles of the logged in user.
# Final linkage between client and server

import getpass
import os
import sqlite3
import time
from datetime import datetime

import audit, client, passwords, server, store

TIME_LIMIT = 180  # 3 minute lockout time and also idle time
MAX_LOGIN_ATTEMPTS = 3

# errors the lower layers raise on purpose (bad input, denied permission, missing file...)
EXPECTED_ERRORS = (ValueError, PermissionError, FileExistsError, FileNotFoundError)

# -----------------------------------
# INPUT HELPERS

# ask a question and return the answer without surrounding spaces
def ask(prompt):
    return input(prompt + "\n").strip()

# ask for a password or passphrase without echoing it to the screen
def ask_secret(prompt):
    return getpass.getpass(prompt + " ")

# ask for a new secret twice, so a typo does not lock the user out of their own key or account
def ask_new_secret(prompt):
    first = ask_secret(prompt)
    if not first:
        raise ValueError("this cannot be empty")

    # confirms the password typed in to prevent typo-ed passwords from being loaded in 
    second = ask_secret("Type it again to confirm:")
    if first != second:
        raise ValueError("the two entries did not match")
    return first

# ask for a cleaned number for the menu options
def ask_int(prompt):
    text = ask(prompt)
    if not text.isdigit():
        raise ValueError("please enter a whole number")
    return int(text)

# -----------------------------------
# FIRST TIME SET UP AND LOGIN

# only an admin can create users, so the very first admin has to be created here
def admin_exists(conn):
    # get all the rows of users
    rows = conn.execute("SELECT roles FROM users").fetchall()
    for row in rows:
        if "admin" in row["roles"].split(","): # check that there is an admin in the active users
            return True
    return False

# called if an admin has not been connected 
def setup_admin(conn):
    print("No admin account has been registered. Please register one.")

    username = ask("Please enter a username:")
    while not username: # get a non null user 
        username = ask("Username not accepted. Please enter a non-empty username:")

    password = ""
    while not password: # get a valid password 
        try:
            password = ask_new_secret("Please enter a password:")
        except ValueError as error:
            print("Password not accepted: " + str(error))

    # hash the password
    hashed = passwords.hash_password(password)

    # load the admin's username and password into the file 
    conn.execute("INSERT INTO users (username, pw_hash, roles) VALUES (?, ?, ?)", (username, hashed, "admin"))
    audit.log(conn, "admin_created", "admin")
    conn.commit()
    print("Registration successful, welcome " + username + ".\n")

# keeps asking until the login works; locks the user out for a while after too many failures
def login_loop(conn):
    user = None
    attempts = 0

    while user is None: # get username and password until valid login
        username = ask("Please enter your username:")
        password = ask_secret("Please enter your password:")

        try:
            user = client.login(conn, username, password)
        except PermissionError:
            attempts += 1 # count the attempts
            print("Invalid username or password.\n")

        # if attempts is maxed out and user is still not given 
        if user is None and attempts >= MAX_LOGIN_ATTEMPTS:
            print("Too many invalid login attempts. Please wait 3 minutes before trying again.\n")
            time.sleep(TIME_LIMIT) # lock them out 
            attempts = 0

    print("Login successful, welcome " + user["username"] + " (" + user["roles"] + ").\n")
    return user


# -----------------------------------
# MENU ACTIONS
# every action takes (conn, user) and either prints a result or raises one of EXPECTED_ERRORS

# every role except admin needs a key pair (admin only handles public keys and metadata)
def generate_keys(conn, user):
    passphrase = ask_new_secret("Choose a passphrase to protect your private key:")
    public_path = client.keygen(user["username"], passphrase) # generate a file for the user 
    print("Key pair created. Ask the admin to register the public key at " + public_path)

def print_log(conn, user):
    rows = client.view_log(conn, user) # get the audit log
    for row in rows: # print it out
        when = datetime.fromtimestamp(row["t"]).strftime("%Y-%m-%d %H:%M:%S")
        print("%4d  %s  %-10s %s" % (row["seq"], when, row["role"], row["action"]))

def check_log(conn, user):
    concerns = audit.verify(conn) # get the list of concerns from the audit
    if not concerns:
        print("Audit log verified: no tampering detected.")
        return

    print("Audit log problems found:")
    for concern in concerns: # list out the concerns in the log
        print("  * " + concern)


# ADMIN

def create_user(conn, user):
    username = ask("Username for the new user:")
    password = ask_new_secret("Password for the new user:")
    try:
        client.create_user(conn, user, username, password) # try to create the user with this username and password
    except sqlite3.IntegrityError:
        raise ValueError("that username is already taken")
    print("Created " + username + " with the sender role.")

def assign_role(conn, user):
    username = ask("Which user should get a new role?")
    role = ask("Which role(s)? Choose from sender, recipient, moderator, admin (separate with commas):")
    client.assign_role(conn, user, username, role) # give the chosen role to the user 
    print("Roles updated for " + username + ".")

def register_key(conn, user):
    username = ask("Register the public key of which user? (they must have generated their keys first)")
    try:
        client.register_key(conn, user, username) # register the given key 
    except FileNotFoundError:
        raise ValueError(username + " has not generated a key pair yet") # if they have not registered the key, the file will be empty 
    print("Public key registered for " + username + ".")

def revoke_key(conn, user):
    username = ask("Revoke the public key of which user?") # get the user
    client.revoke_key(conn, user, username) # revoke the key 
    print("Public key revoked for " + username + ".")

def change_policy(conn, user):
    print("Current policy:") # print out the current rules for the app 
    for key in ("round", "flag_threshold"):
        print("  " + key + " = " + str(server.get_policy(conn, key)))
    key = ask("Which setting would you like to change? (round or flag_threshold)")
    value = ask_int("What is the new value?") # ask for their new value: is it time to issue a new token, new flag threshold, which round is it, etc.
    client.change_policy(conn, user, key, value) # change the policy
    print("Policy updated: " + key + " = " + str(value))

# SENDER
def list_recipients(conn, user): 
    recipients = client.list_recipients(conn, user) # get the active recipients
    if not recipients:
        print("There are no recipients with a registered key yet.")
        return

    # print out the users the sender can send a message to 
    print("You can send a message to:")
    for name in recipients:
        print("  " + name)

def get_token(conn, user): # receive a token
    path = client.get_token(conn, user)
    print("Token issued for this round and saved to " + path)

# the token file for this round is named after the sender and the round (see client.get_token)
def current_token_path(conn, user):
    round_id = server.get_policy(conn, "round") # get the round
    filename = "%s_round%d.token" % (user["username"], round_id) # load the filename
    path = os.path.join(client.tokens_dir(), filename)
    if not os.path.exists(path): # if they cannot find the token path, note that they have not gotten a token
        raise FileNotFoundError("you have no unused token for this round, get one first")
    return path

def send_message(conn, user):
    token_path = current_token_path(conn, user) # get the current toekn
    recipient = ask("Who is the message for?")
    text = ask("What would you like to say? (max " + str(client.MAX_CHARS) + " characters)")
    client.send_message(conn, user, token_path, recipient, text) # request to send the message 
    print("Message sent anonymously to " + recipient + ".")


# RECIPIENT

def read_inbox(conn, user):
    passphrase = ask_secret("Key passphrase:") # ask for recipient passphrase
    messages = client.read_inbox(conn, user, passphrase) # load messages 
    if not messages:
        print("Your inbox is empty.")
        return

    # if messages are not empty, print all of them decrypted to the recipient
    for message_id, round_id, text in messages:
        print("[message " + str(message_id) + ", round " + str(round_id) + "] " + text)

def flag_message(conn, user):
    # ask which message is problematic 
    message_id = ask_int("Which message number would you like to flag?")
    reason = ask("Why is this message abusive?") # ask for a reason
    passphrase = ask_secret("Key passphrase:") # ask for their passphrase 
    client.flag(conn, user, passphrase, message_id, reason)
    print("Message " + str(message_id) + " was flagged and sent to the moderators.")

# MODERATOR CAPABILITIES

def review_flagged(conn, user):
    # ask fot their passphrase
    passphrase = ask_secret("Key passphrase:")
    queue = client.read_queue(conn, user, passphrase) # pass the passphrase along to open the queue
    if not queue: # if the queue is not filled, do nothing
        print("The flagged queue is empty.")
        return

    # otherise, go along with reading the queue: print it out to the user 
    for flag_id, message_id, reason, status, text in queue:
        print("[flag " + str(flag_id) + ", message " + str(message_id) + ", " + status + "]")
        print("  reason:  " + reason)
        print("  message: " + text)

def resolve_flag(conn, user):
    # ask which flag they would like to resolve
    flag_id = ask_int("Which flag number would you like to resolve?")
    client.resolve_flag(conn, user, flag_id)
    print("Flag " + str(flag_id) + " resolved.")

def freeze_token(conn, user):
    # ask which token they would like to freeze by indicating which message is problematic
    message_id = ask_int("Freeze the token behind which flagged message number?")
    client.freeze_token(conn, user, message_id)
    print("The token behind message " + str(message_id) + " is frozen. Its sender stays anonymous.")

# -----------------------------------
# MENU

# each role gets its own list of (label, function)--> these are repeated capabilities between roles 
GENERATE_KEYS = ("Generate my key pair", generate_keys)
VIEW_LOG = ("View the audit log", print_log)
VERIFY_LOG = ("Verify the audit log has not been tampered with", check_log)

# maps all the options to the specific role
ROLE_OPTIONS = {
    "admin": [("Create a user", create_user), ("Assign a role to a user", assign_role), ("Register a user's public key", register_key), ("Revoke a user's public key", revoke_key), ("Change a system policy", change_policy), VIEW_LOG, VERIFY_LOG],
    "moderator": [GENERATE_KEYS, ("Review flagged messages", review_flagged), ("Resolve a flag", resolve_flag), ("Freeze the token behind a flagged message", freeze_token), VIEW_LOG, VERIFY_LOG],
    "recipient": [GENERATE_KEYS, ("Read my inbox", read_inbox), ("Flag a message", flag_message)],
    "sender": [GENERATE_KEYS, ("List who I can send to", list_recipients), ("Get my token for this round", get_token), ("Send an anonymous message", send_message)],
}

# combine the options of all of the user's roles, without listing the same option twice
def build_menu(user):
    options = []
    for role in user["roles"].split(","): # get all the roles
        for option in ROLE_OPTIONS.get(role, []): # get all the capabilities
            if option not in options:
                options.append(option) # add the unique option to the list 
    return options

# print the menu to the user 
def print_menu(options):
    print("What would you like to do?")
    for number, option in enumerate(options, start=1):
        print("  " + str(number) + ") " + option[0])
    print("  q) Quit WhisperChain+")

# runs one menu choice, and reports problems instead of crashing
def run_choice(conn, user, options, choice):
    if not choice.isdigit(): # if the choice they made was not a number
        print("Please enter a valid command.\n")
        return

    # get the index of thier choice
    index = int(choice) - 1
    if index < 0 or index >= len(options): # check validity 
        print("Please enter a valid command.\n")
        return

    # grab the action from the menu of options
    action = options[index][1]
    try:
        action(conn, user) # try to do the action 
    except EXPECTED_ERRORS as error:
        conn.rollback()  # drop anything half finished
        print("Could not complete that action: " + str(error))
    print()

# prompt the options for this user
def run_menu(conn, user):
    options = build_menu(user) # build the specific set of options
    choice = ""

    while choice != "q": # while the user has not quit
        print_menu(options)

        # grab the start time right before asking for input: measuring how long idle behavior goes for
        time_start = time.perf_counter() # start the idle timer
        choice = input().strip().lower() # clean the input
        time_current = time.perf_counter()

        # check if the user has been idle 
        if time_current - time_start > TIME_LIMIT:
            print("Unable to complete action due to inactivity.")
            return

        # if the choice was not to quit
        if choice != "q":
            run_choice(conn, user, options, choice) # run their input

    # otherise if it was quit, print a goodbye message which returns to main 
    print("Now quitting WhisperChain+. Goodbye.")


def main():
    # open db. 
    conn = store.connect()
    try:
        # if an admin has not been set up 
        if not admin_exists(conn):
            setup_admin(conn) # set one up
        user = login_loop(conn) # login
        run_menu(conn, user) # give options
    except (EOFError, KeyboardInterrupt): # if a user control c
        print("\nInput closed. Goodbye.")
    finally:
        conn.close() # close the db

# run main
if __name__ == "__main__":
    main()
