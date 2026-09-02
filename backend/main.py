import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from database import engine, Base
import routes

load_dotenv()

# --- Structured logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("garud_ai")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize resources on startup, clean up on shutdown."""
    logger.info("GARUD-AI API starting up...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables verified/created.")
    yield
    logger.info("GARUD-AI API shutting down.")


app = FastAPI(
    title="GARUD-AI CyberShield API",
    version="1.0.0",
    description="AI-powered Android APK malware analysis and threat intelligence platform.",
    lifespan=lifespan,
)

# --- CORS ---
# Read allowed origins from env. Supports multiple comma-separated values.
raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173")
allowed_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]
logger.info(f"CORS allowed origins: {allowed_origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes.router)


@app.get("/", tags=["health"])
def health_check():
    return {"status": "GARUD-AI API is running", "version": "1.0.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,   # Never use reload=True in production
    )
