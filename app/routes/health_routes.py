from fastapi import APIRouter
from datetime import datetime

router = APIRouter()


@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "AI Cloud Security Monitor"
    }


@router.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "AI Cloud Security Monitor API",
        "version": "1.0.0",
        "docs": "/docs"
    }
