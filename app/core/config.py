import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Supabase settings
SUPABASE_URL: str = os.getenv("SUPABASE_URL")
SUPABASE_KEY: str = os.getenv("SUPABASE_KEY")

# Server settings
PROJECT_NAME: str = "EPIC Server"
PORT: int = int(os.getenv("PORT", 8000))
SSL_KEYFILE: str = os.getenv("SSL_KEYFILE", "key.pem") # TODO: Consider if these defaults are secure for all environments
SSL_CERTFILE: str = os.getenv("SSL_CERTFILE", "cert.pem") # TODO: Consider if these defaults are secure for all environments

# CORS settings
ALLOW_ORIGINS = ["*"] # TODO: Restrict this in production 