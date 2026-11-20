# WhisperChain Anonymous: Joanna, Dejanae, Megan 

## Set up:
Run ```main.py``` which sets up a continous CLI interface. If an admin has not been registered, you will be prompted to register one. Once a user has logged in, they are able to send requests via calling the functions in ```client.py```. These requests will be validated and enacted by ```server.py```, using the backend files in the repository. Users can only request actions specific to their role; the server should not carry out any actions that the user is not permitted to. 


## Overview: 
Our implementation of WhisperChain Anonymous has none of the extended features. We have implemented pseudorandom ID tokens for token issuance, hash chaining for the audit logs, described - and implicit - permissions and capabilities delineated in the assignment, and a quasi "server-client" set up with a command line interface. 

