class RiskEngine:

    def __init__(self):

        self.score = 0

    # -----------------------------
    # Generic
    # -----------------------------

    def add(self, severity):

        severity = severity.upper()

        if severity == "LOW":

            self.score += 5

        elif severity == "MEDIUM":

            self.score += 10

        elif severity == "HIGH":

            self.score += 20

        elif severity == "CRITICAL":

            self.score += 30

    def add_custom(self, value):

        self.score += value

    # -----------------------------
    # Hidden Processes
    # -----------------------------

    def hidden_processes(self, count):

        self.score += min(
            count * 40,
            60
        )

    # -----------------------------
    # Hidden Modules
    # -----------------------------

    def hidden_modules(self, count):

        self.score += min(
            count * 20,
            40
        )

    # -----------------------------
    # Persistence
    # -----------------------------

    def persistence(self, count):

        self.score += min(
            count * 20,
            40
        )

    # -----------------------------
    # Kernel Hooks
    # -----------------------------

    def kernel_hooks(self, count):

        self.score += min(
            count * 5,
            15
        )

    # -----------------------------
    # Kernel Panic
    # -----------------------------

    def kernel_panic(self):

        self.score += 35

    # -----------------------------
    # Kernel Taint
    # -----------------------------

    def kernel_taint(self):

        self.score += 30

    # -----------------------------
    # Final Score
    # -----------------------------

    def total(self):

        return min(
            self.score,
            100
        )

    # -----------------------------
    # Threat Level
    # -----------------------------

    def level(self):

        score = self.total()

        if score < 25:

            return "LOW"

        elif score < 50:

            return "MEDIUM"

        elif score < 75:

            return "HIGH"

        return "CRITICAL"
