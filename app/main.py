from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
import uvicorn
import os
import ssl

from app.core.config import PROJECT_NAME, ALLOW_ORIGINS, PORT, ssl_config, ENVIRONMENT
from app.routers import auth_router, files_router, user_router, health_router
from app.core.rate_limiter import RateLimiter

app = FastAPI(title=PROJECT_NAME, description="Server for CS4455 Epic Project")

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security middleware
if ENVIRONMENT in ["production", "staging"]:
    app.add_middleware(HTTPSRedirectMiddleware)
    app.add_middleware(
        TrustedHostMiddleware, 
        allowed_hosts=["yourdomain.com", "*.yourdomain.com"]
    )

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

# Include routers
app.include_router(auth_router.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(files_router.router, prefix="/api/files", tags=["Files"])
app.include_router(user_router.router, prefix="/api/user", tags=["User"])
app.include_router(health_router.router, prefix="/api/health", tags=["Health"])


@app.get("/")
async def root():
    return {"message": f"{PROJECT_NAME} is running."}

# TODO: Move the uvicorn run command to a separate run.py or manage.py at the project root
# This is for when you run the app directly using `python app/main.py`
# For production, you'd typically use `uvicorn app.main:app --reload`
if __name__ == "__main__":
    # Get SSL context
    ssl_context = ssl_config.get_ssl_context()
    
    uvicorn_config = {
        "app": "app.main:app",
        "host": "0.0.0.0",
        "port": PORT,
        "reload": ENVIRONMENT == "development"
    }
    
    # Add SSL configuration if available
    if ssl_context:
        uvicorn_config.update({
            "ssl_keyfile": ssl_config.ssl_keyfile,
            "ssl_certfile": ssl_config.ssl_certfile,
            "ssl_version": ssl.PROTOCOL_TLS_SERVER,
            "ssl_cert_reqs": ssl.CERT_NONE,  # Adjust based on your needs
        })
    
    uvicorn.run(**uvicorn_config) 