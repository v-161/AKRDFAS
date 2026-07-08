class ModuleRisk:

    def __init__(self):
        pass

    def evaluate(self, module):

        score = 0
        reasons = []

        # Module file missing
        if not module["path"]:

            score += 40

            reasons.append(
                "Module file could not be located."
            )

        # Hash unavailable
        if not module["sha256"]:

            score += 25

            reasons.append(
                "SHA256 hash unavailable."
            )

        # Missing license
        if not module["license"]:

            score += 10

            reasons.append(
                "License information missing."
            )

        # Missing description
        if not module["description"]:

            score += 5

            reasons.append(
                "Description unavailable."
            )

        # Risk Level
        if score >= 60:
            level = "HIGH"

        elif score >= 30:
            level = "MEDIUM"

        else:
            level = "LOW"

        return {

            "score": score,

            "level": level,

            "reasons": reasons

        }