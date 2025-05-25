from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from app.core.config import PROJECT_NAME, ALLOW_ORIGINS, PORT, SSL_KEYFILE, SSL_CERTFILE
from app.routers import auth_router, files_router, user_router

app = FastAPI(title=PROJECT_NAME, description="Server for CS4455 Epic Project")

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(files_router.router, prefix="/api/files", tags=["Files"])
app.include_router(user_router.router, prefix="/api/user", tags=["User"])


@app.get("/")
async def root():
    return {"message": f"{PROJECT_NAME} is running."}

# TODO: Move the uvicorn run command to a separate run.py or manage.py at the project root
# This is for when you run the app directly using `python app/main.py`
# For production, you'd typically use `uvicorn app.main:app --reload`
if __name__ == "__main__":
    uvicorn.run(
        "app.main:app", # Point to the app instance
        host="0.0.0.0",
        port=PORT,
        reload=True, # Useful for development
        ssl_keyfile=SSL_KEYFILE if SSL_KEYFILE and SSL_CERTFILE else None,
        ssl_certfile=SSL_CERTFILE if SSL_KEYFILE and SSL_CERTFILE else None
    ) 