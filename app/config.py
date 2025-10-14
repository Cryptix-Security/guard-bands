import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    SECRET_KEY: bytes = os.getenv("SECRET_KEY", "default-secret-key-change-me").encode('utf-8')
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    DEBUG: bool = os.getenv("DEBUG", "True").lower() == "true"

settings = Settings()
