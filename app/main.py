from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import uvicorn

from app.core.config import PROJECT_NAME, ALLOW_ORIGINS, ENVIRONMENT
from app.routers import auth_router, files_router, user_router  # , health_router

app = FastAPI(title=PROJECT_NAME, description="Server for CS4455 Epic Project")

# CORS Middleware - Allows cross-origin requests from specified domains (enables web browsers to access API from different ports/domains)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security middleware for production - validates request host headers
if ENVIRONMENT in ["production", "staging"]:
    app.add_middleware(
        TrustedHostMiddleware,  # Blocks requests with malicious Host headers
        allowed_hosts=["chrisplusplus.gobbler.info", "*.gobbler.info"]
    )

# Security headers middleware - Adds protective HTTP headers to every response to prevent common web attacks
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"  # Prevents MIME sniffing attacks
    response.headers["X-Frame-Options"] = "DENY"  # Prevents clickjacking by blocking iframe embedding
    response.headers["X-XSS-Protection"] = "1; mode=block"  # Enables browser XSS filtering
    # Don't set HSTS - Apache handles this
    response.headers["Content-Security-Policy"] = "default-src 'self'"  # Only allows resources from same domain
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    return response

# Include routers
app.include_router(auth_router.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(files_router.router, prefix="/api/files", tags=["Files"])
app.include_router(user_router.router, prefix="/api/user", tags=["User"])
# app.include_router(health_router.router, prefix="/api/health", tags=["Health"])


@app.get("/")
async def root():
    return {"message": f"{PROJECT_NAME} is running."}

# TODO: Move the uvicorn run command to a separate run.py or manage.py at the project root
# This is for when you run the app directly using `python app/main.py`
# For production, you'd typically use `uvicorn app.main:app --reload`
if __name__ == "__main__":
    uvicorn_config = {
        "app": "app.main:app",
        "host": "127.0.0.1",  # Internal only - Apache handles external access
        "port": 3010,         # Your assigned port
        "reload": ENVIRONMENT == "development"
    }
    
    uvicorn.run(**uvicorn_config) 