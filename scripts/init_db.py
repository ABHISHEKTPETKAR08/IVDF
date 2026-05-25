"""
Database initialisation script.
Run once before starting the backend for the first time:

    python scripts/init_db.py
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from backend.database.db import init_db
from backend.utils.logger import setup_logging, get_logger

setup_logging()
logger = get_logger(__name__)


async def main():
    logger.info("Initialising database…")
    await init_db()
    logger.info("Database ready.")


if __name__ == "__main__":
    asyncio.run(main())
