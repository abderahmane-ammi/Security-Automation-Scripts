import re

class LogAnalyzer:
    def __init__(self, logfile):
        self.logfile = logfile
        self.suspicious_patterns = [
            re.compile(r"Failed login attempt from (\d+\.\d+\.\d+\.\d+)"),
            re.compile(r"SQL error:.*' OR '1'='1")
        ]

    def analyze(self):
        with open(self.logfile, 'r') as file:
            logs = file.readlines()
        for log in logs:
            self.check_suspicious(log)

    def check_suspicious(self, log):
        for pattern in self.suspicious_patterns:
            match = pattern.search(log)
            if match:
                self.alert(log)

    def alert(self, log):
        print(f"Suspicious log entry found: {log}")

# Example usage
analyzer = LogAnalyzer("/var/log/server.log")
analyzer.analyze()
