from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.routes import health_routes, scan_routes, anomaly_routes, report_routes

# Initialize FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI-powered cloud security monitoring system for AWS",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health_routes.router, prefix=settings.API_V1_PREFIX, tags=["Health"])
app.include_router(scan_routes.router, prefix=settings.API_V1_PREFIX, tags=["Scans"])
app.include_router(anomaly_routes.router, prefix=settings.API_V1_PREFIX, tags=["Anomalies"])
app.include_router(report_routes.router, prefix=settings.API_V1_PREFIX, tags=["Reports"])


@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    print(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on application shutdown"""
    print(f"Shutting down {settings.APP_NAME}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG
    )
