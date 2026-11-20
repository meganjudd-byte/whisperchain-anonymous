# Role Based Access Control 

# enforce no typos or made up roles 
from enum import Enum

# RBAC has a table with roles and the permissions they have

# first, wrap every possible role into one class
class Role(str, Enum):  # only define these roles, enforce exact matching so that typos do not indicate a role
    SENDER = "sender"
    RECIPIENT = "recipient"
    MODERATOR = "moderator"
    ADMIN = "admin"


# now create the permissions 
class Permissions(str, Enum):
    CREATE_USER = "create_user" # admin creates users --> implicit key registration and assignment
    ASSIGN_ROLE = "assign_role" # admin assigns roles
    ROTATE_POLICY = "rotate_policy" # only admin can decide WhisperChain policy 
    REGISTER_KEY = "register_key" # admin registers a key for each user 
    REVOKE_KEY = "revoke_key" # revoke a key 

    VIEW_LOG = "view_log" # only moderators & admin can review logs
    
    FREEZE_TOKEN = "freeze_token" # only moderators can freeze
    VIEW_FLAGGED = "view_flagged" # only moderators can review flagged
    RESOLVE_FLAG = "resolve_flag" # moderators can resolve flags 
    
    READ_MESSAGES = "read_messages" # ensure that only the recipient can get messages
    FLAG_MESSAGE = "flag_message" # recipient can flag something offensive 
    GET_TOKEN = "get_token" # senders can request a token to send messages
    GET_RECIPIENT_KEY = "get_recipient_key" # senders need the recipient's key in order to send messages
    SEND_MESSAGE = "send_message"
    GET_MOD_KEY = "get_mod_key" # recipients can request the moderators key to encrypt messages that are flagged
    VIEW_RECIPIENTS = "view_recipients" # senders can view who they could possibly send a message to 
   

# map each role to their permissions and store in this dictionary
PERMISSIONS = {Role.SENDER: {Permissions.GET_TOKEN, Permissions.GET_RECIPIENT_KEY, Permissions.SEND_MESSAGE, Permissions.VIEW_RECIPIENTS},
                Role.RECIPIENT: {Permissions.READ_MESSAGES, Permissions.FLAG_MESSAGE, Permissions.GET_MOD_KEY},
                Role.MODERATOR: {Permissions.VIEW_LOG, Permissions.FREEZE_TOKEN, 
                                 Permissions.RESOLVE_FLAG, Permissions.VIEW_FLAGGED},
                Role.ADMIN: {Permissions.CREATE_USER, Permissions.ASSIGN_ROLE, Permissions.VIEW_LOG, 
                             Permissions.ROTATE_POLICY, Permissions.REGISTER_KEY, Permissions.REVOKE_KEY}
                }

def has_permission(roles, perm): # check which roles have this permission
    # enumerate the perm 
    try:
        perm = Permissions(perm)
    except ValueError:
        return False

    # loop over all the roles to see if it is found in the permissions 
    for r in roles: 
        try: # try to find the permission for that role
            role = Role(r) 
        except ValueError:
            continue

        if perm in PERMISSIONS[Role(r)]:
                return True
        
    return False # if none of the roles have that permission 