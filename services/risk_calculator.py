from config import Config

def calculate_risk_score(findings):
    score = 0
    weights = Config.RISK_WEIGHTS
    
    # Simple scoring logic
    critical = len([f for f in findings if f.get("severity") == "critical"])
    high = len([f for f in findings if f.get("severity") == "high"])
    
    score = min(100, (critical * 25) + (high * 15))
    
    return {
        "overall_score": score,
        "risk_level": "high" if score > 70 else "medium" if score > 40 else "low",
        "peca_min_pkr": Config.PECA_FINES.get("high", {}).get("min_pkr", 0),
        "peca_max_pkr": Config.PECA_FINES.get("high", {}).get("max_pkr", 0)
    }