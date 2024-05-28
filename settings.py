import os
from loguru import logger

from dotenv import load_dotenv

PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))

load_dotenv(verbose=True, dotenv_path=os.path.join(PROJECT_ROOT, '.env'))

# Number of rows processed with every batch.
ROWS_NUMBER = os.getenv("ROWS_NUMBER")

# path to file with ngram combinations.
NGRAM_PATH = os.getenv("NGRAM_PATH")

# path to dataset file.
DATASET_PATH = os.getenv("DATASET_PATH")

# path to model file.
MODEL_PATH = os.getenv("MODEL_PATH")

# auth creds.
USER_NAME = os.getenv("USER_NAME")
USER_PASS = os.getenv("USER_PASS")

# web settings 
SERVICE_HOST = os.getenv("SERVICE_HOST")
SERVICE_PORT = os.getenv("SERVICE_PORT")

# URL address
WEBSITE_ADDRESS= os.getenv("WEBSITE_ADDRESS")

# Services:
# VirustTotal
VIRUS_TOTAL_REPORT_URL = os.getenv("VIRUS_TOTAL_REPORT_URL")
VIRUS_TOTAL_SCAN_URL = os.getenv("VIRUS_TOTAL_SCAN_URL")
VIRUS_TOTAL_API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")

# api blacklist checker - (can check: email, domain or IP address)
BLACKLIST_CHECKER_API_KEY = os.getenv("BLACKLIST_CHECKER_API_KEY")
BLACKLIST_CHECKER_URL = os.getenv("BLACKLIST_CHECKER_URL")

logger.add(
    sink=os.path.join("debug_logs", "warning.log"),
    level="WARNING",
    rotation="1 day",
    compression="zip",
    encoding="utf-8",
    enqueue=True,
    backtrace=True,
    diagnose=False,
    serialize=True
)