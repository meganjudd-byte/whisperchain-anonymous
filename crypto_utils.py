# Utilities for encryption 
# We need functionality for: 
#   1. Generating keypairs for users 
#   2. Encrypting messages
#   3. Decrypting messages 
# Notes: 
# RSA key pairs are cryptographic primitives, so you need to serialize them (pem) before storing 

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64

# RSA requires a padding scheme, OAEP is recommended
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

# helpers for SQL storage: going from bytes to base 64, and then base 64 to bytes
def b64(data):
    return base64.b64encode(data).decode()

def unb64(text):
    return base64.b64decode(text)

# Generate an RSA-2048: 2048 bit key size to protect against exhaustive search; public exponent is standard
def generate_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

""" Logistical helpers """
# helper function to encrypt the private key and serialize
def private_to_pem(key, passphrase):
    # the private key file is encrypted with a passphrase, so a stolen file is not enough
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.BestAvailableEncryption(passphrase.encode()))

# helper function to safely store the public key serialized 
def public_to_pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()

# helper function to load the private key given a pem and the passphrase used in encryption 
def load_private(pem, passphrase):
    return serialization.load_pem_private_key(pem, password=passphrase.encode())

# helper function to load the public key 
def load_public(pem):
    return serialization.load_pem_public_key(pem.encode() if isinstance(pem, str) else pem)

# functionality to actually encrypt and decrypt 
def encrypt(public_pem, plaintext):
    # encrypt the plaintext with a given pem --> load a public key 
    
    # encrypt with symmetric cryptography giving the first layer 
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), None)
    
    # hybrid encryption: send the symmetric key over safely
    #  with the public key, so only the owner of the associated private key can read it, and then therefore
    # ideally, only the receiver can view the plaintext 
    wrapped_key = load_public(public_pem).encrypt(aes_key, OAEP)
    return b64(ciphertext), b64(wrapped_key), b64(nonce) # return everything ready to be stored

# functionality to decrypt 
def decrypt(priv_key, ciphertext, wrapped_key, nonce):
    # get the symmetric key
    aes_key = priv_key.decrypt(unb64(wrapped_key), OAEP)
    # GCM also checks the message was not changed; it raises an error if it was
    return AESGCM(aes_key).decrypt(unb64(nonce), unb64(ciphertext), None).decode("utf-8") # return decrypted plaintext 

# unwraps an encrypted key and then rewraps it --> helper for flagging messages
def rewrap_key(priv_key, wrapped_key, mod_public_pem):
    aes_key = priv_key.decrypt(unb64(wrapped_key), OAEP)
    return b64(load_public(mod_public_pem).encrypt(aes_key, OAEP))

