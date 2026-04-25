import logging

logger = logging.getLogger("CyberAttackDetector.DB")

class Database:
    def __init__(self):
        logger.info("Initializing Database Connection (SQLite/PostgreSQL stub)")
        self.alerts_table = []

    def save_alert(self, alert_report):
        """Saves a generated threat alert to the database."""
        self.alerts_table.append(alert_report)

    def get_recent_alerts(self, limit=50):
        """Retrieves the most recent alerts."""
        return list(reversed(self.alerts_table[-limit:]))
