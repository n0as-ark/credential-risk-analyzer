import math
from collections import Counter

def get_character_pools(password: str) -> dict:
    """return which character categories are present in the password:
    lowercase, uppercase, digits, special characters (! @ # $ % ^ & * - _ + = ?)
    
    >>> get_character_pools("Hello123!")
    {'lower': True, 'upper': True, 'digit': True, 'special': True}

    >>> get_character_pools("")
    {'lower': False, 'upper': False, 'digit': False, 'special': False}

    >>> get_character_pools("ABC123")
    {'lower': False, 'upper': True, 'digit': True, 'special': False}

    >>> get_character_pools("pass word~")
    {'lower': True, 'upper': False, 'digit': False, 'special': False}
    """

    #create a dictionary with four character pools, all defaulting to False
    char_pools = dict.fromkeys(["lower", "upper", "digit", "special"], False)

    SPECIAL = "!@#$%^&*-_+=?"

    for c in password:
        if c.islower(): 
            char_pools["lower"] = True
        elif c.isupper(): 
            char_pools["upper"] = True
        elif c.isdigit(): 
            char_pools["digit"] = True
        elif c in SPECIAL: 
            char_pools["special"] = True

    return char_pools

def get_pool_size(password: str) -> int:
    """return the total character pool size, using these sizes: 
    lowercase=26, uppercase=26, digits=10, special characters= 13

    >>> get_pool_size("")
    0

    >>> get_pool_size("abc")
    26

    >>> get_pool_size("Abc123")
    62

    >>> get_pool_size("Hello123!")
    75

    >>> get_pool_size("Hello world~")
    52
    """

    LOWER = 26
    UPPER = 26
    DIGIT = 10
    SPECIAL = 13

    char_pools = get_character_pools(password)

    size = 0

    if char_pools["lower"]:
        size += LOWER
    if char_pools["upper"]:
        size += UPPER
    if char_pools["digit"]:
        size += DIGIT
    if char_pools["special"]:
        size += SPECIAL

    return size

def calculate_entropy(password: str) -> float:
    """return the entropy of the given password using the formula:
    entropy_bits = length x log2(pool_size)
    The empty-string case will return `0.0` without raising an error

    >>> calculate_entropy("")
    0.0

    >>> round(calculate_entropy("a"), 2)
    4.7

    >>> round(calculate_entropy("abc"), 2)
    14.1

    >>> round(calculate_entropy("Hello123!"), 2)
    56.06
    """

    pool_size = get_pool_size(password)

    if pool_size == 0:
        return 0.0
    else:
        return len(password)*math.log2(pool_size)

def calculate_shannon_entropy(password: str) -> float:
    """return the Shannon entropy of the given password using the formula:
    -sum( p(c) x log2(p(c)) for each unique character c )
    where p(c) = count of c / length of password

    The result is multiplied by the length of the password so the units
    (total bits) are comparable to calculate_entropy().
    The empty-string case will return `0.0` without raising an error.
    
    >>> calculate_shannon_entropy("")
    0.0

    >>> calculate_shannon_entropy("aaaa")
    0.0

    >>> calculate_shannon_entropy("abab")
    4.0

    >>> round(calculate_shannon_entropy("Hello123!"), 2)
    26.53
    """

    if not password:    # if password is an empty string
        return 0.0

    length = len(password)
    counts = Counter(password)  # counts how many times each character appears

    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy += p * math.log2(1/p)   # same as -p x log2(p)

    return entropy * length     # total for the whole password