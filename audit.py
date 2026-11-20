# Logging functionality: stores the actions taken by specific roles, not users
# Append only --> editing a middle or higher up row will be detected 
# Need to implement logging that upholds accountability, but does not compromise anonymity 
#   * log when tokens are issued 
#   * log when tokens are used (message sent) 
#   * log when messages are flagged 

# need functionality to log and then verify the logs 

import hashlib, time

# one way to detect tampering is to calculate a hash for each entry based on the previous one and the current entry 
# any tampering would be detected by verify function 

FIRST = "0" * 64  # "previous hash" of the first row
# this is a helper for chain hashing 
def chain_hash(prev, seq, t, action, role):
    return hashlib.sha256(("%s|%d|%.6f|%s|%s" % (prev, seq, t, action, role)).encode()).hexdigest()

# first, implement the logging 
def log(conn, action, role):
    t = time.time() # record the time when log is being called ~= when action was taken
    # grab the last entry 
    last = conn.execute("SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()

    # check if the last entry is none --> first log entry
    if last is None:
        seq = 1 # use the data for first log entry 
        prev = FIRST
    else: # otherwise there is a previous entry 
        seq = last["seq"] + 1 # move forward in the sequence
        prev = last["entry_hash"] # get the hash of the previous entry 
    entry_hash = chain_hash(prev, seq, t, action, role) # chain

    # drop it in the log
    conn.execute("INSERT INTO audit_log (seq, t, action, role, prev_hash, entry_hash) "
                 "VALUES (?, ?, ?, ?, ?, ?)", (seq, t, action, role, prev, entry_hash))

# now, using our chain of hashes, we can verify that entries were not tampred with 
def verify(conn):
    # look over the log and return the problems we find 
    concerns = []
    prev = FIRST # track the hashes
    expected_seq = 1 # march down the sequence 

    for row in conn.execute("SELECT * FROM audit_log ORDER BY seq"):
        # if the row is not the expected number: something got out of order or inserted
        if row["seq"] != expected_seq: 
            concerns.append("row(s) missing before seq %d" % row["seq"])
            expected_seq = row["seq"]

        # make sure that the previous hash matches what it should be
        if row["prev_hash"] != prev: 
            concerns.append("seq %d: chain broken (prev_hash does not match)" % row["seq"])

        # calculate the hash chain to ensure it matches
        if row["entry_hash"] != chain_hash(row["prev_hash"], row["seq"], row["t"], row["action"], row["role"]):
            concerns.append("seq %d: contents were changed" % row["seq"])

        # continue down the log
        prev = row["entry_hash"]
        expected_seq += 1
    return concerns