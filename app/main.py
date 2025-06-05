from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware as StarletteTrustedHostMiddleware
import uvicorn

from app.core.config import PROJECT_NAME, ALLOW_ORIGINS, ENVIRONMENT
from app.routers import auth_router, files_router, user_router  # , health_router

app = FastAPI(title=PROJECT_NAME, description="Server for CS4455 Epic Project")

# Proxy Headers Middleware - Handle Apache proxy headers
@app.middleware("http")
async def proxy_headers_middleware(request: Request, call_next):
    # Handle Apache proxy headers
    if "x-forwarded-proto" in request.headers:
        request.scope["scheme"] = request.headers["x-forwarded-proto"]
    if "x-forwarded-host" in request.headers:
        request.scope["server"] = (request.headers["x-forwarded-host"], None)
    if "x-forwarded-for" in request.headers:
        # Get the original client IP and use a default port to avoid uvicorn logging errors
        original_ip = request.headers["x-forwarded-for"].split(",")[0].strip()
        request.scope["client"] = (original_ip, 0)  # Use port 0 instead of None
    
    response = await call_next(request)
    return response

# CORS Middleware - Allows cross-origin requests from specified domains (enables web browsers to access API from different ports/domains)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"  # Prevents MIME sniffing attacks
    response.headers["X-Frame-Options"] = "DENY"  # Prevents clickjacking by blocking iframe embedding
    response.headers["X-XSS-Protection"] = "1; mode=block"  # Enables browser XSS filtering
    # Updated CSP to allow inline styles and scripts for better compatibility with frontend frameworks
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    return response

# Include routers
app.include_router(auth_router.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(files_router.router, prefix="/api/files", tags=["Files"])
app.include_router(user_router.router, prefix="/api/user", tags=["User"])
# app.include_router(health_router.router, prefix="/api/health", tags=["Health"])

@app.get("/")
async def root():
    return {"message": f"{PROJECT_NAME} is running."}

if __name__ == "__main__":
    uvicorn_config = {
        "app": "app.main:app",
        "host": "0.0.0.0",    # Allow external connections for Apache proxy
        "port": 3010,         # Your assigned port
        "reload": ENVIRONMENT == "development",
        "forwarded_allow_ips": "*"  # Trust proxy headers from any IP (since Apache is handling this)
    }
    uvicorn.run(**uvicorn_config) 