from src.entropy import calculate_entropy
from src.breach_check import check_breach

"""
Scoring Rules:
1. Breach match (count of 1 or more):
the score starts at 80 and rises by 4 points for every factor of ten in the count, capped at 100
2. No breach match: the formula for calculating the score is 10 + 60 x (1 - min(entropy, 80)/80);
entropy of 0 gives 70, and entropy of 80 bits or more gives 10, so risk falls steadily as entropy rises
3. Labels: 10-29 is LOW, 30-59 is MEDIUM, and 60-100 is HIGH.
"""

def calculate_risk_score(entropy_bits: float, breach_count: int) -> float:
    """return a risk score from 10 to 100 (higher = riskier).
    
    Breached passwords score 80 and up, gaining 4 points per factor of ten
    in the breach count, capped at 100. Passwords with no breach match score
    from 70 (0 bits) down to 10 (80 bits or more).

    >>> calculate_risk_score(37.6, 52372427)
    100
    >>> calculate_risk_score(0, 0)
    70.0
    >>> calculate_risk_score(80, 0)
    10.0
    >>> round(calculate_risk_score(37.6, 0), 1)
    41.8
    """
    if breach_count > 0:
        risk_score = 80
        remainder = breach_count

        while remainder >= 10:
            risk_score += 4    # gain 4 points per factor of ten
            remainder = remainder // 10
        if risk_score > 100:
            risk_score = 100
    else:
        risk_score = 10 + 60 * (1 - min(entropy_bits, 80)/80)

    return risk_score

def risk_label(risk_score: float) -> str:
    """return a label based on the given risk score.

    LOW below 30, MEDIUM from 30 up to (but not including) 60, and HIGH from 60.

    >>> risk_label(0)
    'LOW'
    >>> risk_label(29.9)
    'LOW'
    >>> risk_label(59.9)
    'MEDIUM'
    >>> risk_label(100)
    'HIGH'
    """
    if risk_score < 30:
        return 'LOW'
    elif risk_score < 60:
        return 'MEDIUM'
    else:
        return 'HIGH'

def analyze(entropy_bits: float, breach_count: int) -> dict:
    """return a dictionary containing the entropy, breach status, 
    breach count, risk score, and risk label of the password.

    >>> analyze(37.6, 52372427)
    {'Entropy': 37.6, 'Breach Status': True, 'Breach Count': 52372427, 'Risk Score': 100, 'Risk Label': 'HIGH'}
    >>> analyze(130.8, 0)
    {'Entropy': 130.8, 'Breach Status': False, 'Breach Count': 0, 'Risk Score': 10.0, 'Risk Label': 'LOW'}
    """
    result = {}
    result['Entropy'] = entropy_bits

    if breach_count > 0:
        result['Breach Status'] = True
    else:
        result['Breach Status'] = False

    result['Breach Count'] = breach_count

    risk_score = calculate_risk_score(entropy_bits, breach_count)
    result['Risk Score'] = risk_score
    result['Risk Label'] = risk_label(risk_score)

    return result
