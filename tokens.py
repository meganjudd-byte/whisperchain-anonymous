# Each sender needs to receive a random, anonymous token per round 
# This is a pseudorandom ID 

import secrets, hashlib 

# all we need to do is generate random ID, and issue it 
def generate_token():
    return secrets.token_bytes(32)

# hash the token for storage
def hash_token(token):
    return hashlib.sha256(token).hexdigest()