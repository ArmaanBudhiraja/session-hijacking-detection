from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings
from app.db.session import engine, Base
import app.models  # Ensure all models are registered with Base metadata
from app.api.routes import auth, security, sessions, demo

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables
    Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "Academic Web Security Project: Behavioral Fingerprint-Based Detection "
        "of Session Hijacking in Web Applications. "
        "Developed by Anish Jaiswal (23BCE0172) & Armaan Budhiraja (23BCE0507)."
    ),
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# CORS Middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["set-cookie"]
)

# Global Exception Handlers
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "status_code": exc.status_code,
            "message": exc.detail
        }
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": True,
            "status_code": 422,
            "message": "Validation error in request parameters or body.",
            "details": exc.errors()
        }
    )

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": True,
            "status_code": 500,
            "message": "Internal server error occurred."
        }
    )

# Routers
app.include_router(auth.router, prefix="/api")
app.include_router(security.router, prefix="/api")
app.include_router(sessions.router, prefix="/api")
app.include_router(demo.router, prefix="/api")

@app.get("/", tags=["Root"])
def root_index():
    """
    Root endpoint providing service metadata and direct navigation links
    for evaluators visiting http://localhost:8000 directly.
    """
    return {
        "app": settings.APP_NAME,
        "status": "online",
        "version": "1.0.0",
        "documentation": "/api/docs",
        "redoc": "/api/redoc",
        "health": "/api/health",
        "authors": [
            "Anish Jaiswal (23BCE0172)",
            "Armaan Budhiraja (23BCE0507)"
        ],
        "frontend_url": "http://localhost:5173"
    }

@app.get("/api/health", tags=["Health"])
@app.get("/health", tags=["Health"])
def health_check():
    """Health check endpoint to verify backend operational readiness."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "environment": settings.ENVIRONMENT,
        "version": "1.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
