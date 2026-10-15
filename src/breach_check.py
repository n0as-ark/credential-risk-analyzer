import hashlib
import requests

API_URL = "https://api.pwnedpasswords.com/range/"
USER_AGENT = "credential-risk-analyzer/0.1 (+https://github.com/n0as-ark/credential-risk-analyzer)"

def hash_password(password: str) -> str:
    """return the uppercase SHA-1 hex digest of the password
    
    >>> hash_password("password")
    '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8'
    >>> hash_password("P@ssw0rd")
    '21BD12DC183F740EE76F27B78EB39C8AD972A757'
    """
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

def check_breach(password:str, timeout: int = 5) -> int:
    """return how many times a password appears in known breaches (0 if none).
    """
    hashed = hash_password(password)
    # Only the 5-character prefix is sent
    prefix, suffix = hashed[:5], hashed[5:]

    response = requests.get(
        API_URL + prefix,
        headers={"User-Agent": USER_AGENT},
        timeout=timeout,
        )

    response.raise_for_status() # raise an error on a bad status

    for line in response.text.splitlines():
        line_suffix, count = line.split(":")    # cut each line into the suffix and the count
        if line_suffix == suffix:       # hashed value of the password is found in the breach data
            return int(count)

    # not in the results, so no known breach
    return 0