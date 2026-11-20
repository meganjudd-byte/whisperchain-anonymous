# Functionality to store passwords 
# Similar hashing logic to CLI pwd manager 

import hashlib, secrets 

# need to create a unique hash for each password
def hash_password(pswd):
    # salt to protect against rainbow table attack
    salt = secrets.token_bytes(16)
    # hash the password 
    hashed = hashlib.pbkdf2_hmac('sha256', pswd.encode('utf-8'), salt, 600000) # OSWAP suggests 600,000 iterations 

    # store in sql format: salt : hash 
    return salt.hex() + ":" + hashed.hex()

# check an inputted password against what was stored
def check_password(input, stored):
    try:
        salt_hex, hashed_hex = stored.split(":") # grab salt and hash
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False # dont accept any malformed data  

    input_hashed = hashlib.pbkdf2_hmac('sha256', input.encode('utf-8'), salt, 600000)

    if hashed_hex == input_hashed.hex():
        return True # return true if the password was correct
    return False
