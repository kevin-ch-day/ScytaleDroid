"""
db_config.py - Database configuration for ScytaleDroid
"""

from typing import Dict, Union

# Database connection settings
DB_CONFIG: Dict[str, Union[str, int]] = {
    "host": "localhost",
    "port": 3306,
    "user": "root",
    "password": "Password123!",
    "database": "scytaledroid_droid_intel_db_dev",
    "charset": "utf8mb4",
}
