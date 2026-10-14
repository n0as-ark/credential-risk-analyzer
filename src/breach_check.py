import hashlib

def hash_password(password: str) -> str:
    """return the uppercase SHA-1 hex digest of the password
    
    >>> hash_password("password")
    '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8'
    >>> hash_password("P@ssw0rd")
    '21BD12DC183F740EE76F27B78EB39C8AD972A757'
    """
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
