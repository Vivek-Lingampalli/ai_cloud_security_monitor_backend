from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime
from app.db.database import get_db
from app.db import crud

router = APIRouter()


@router.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """Health check endpoint with database statistics"""
    try:
        stats = crud.get_statistics(db)
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "service": "AI Cloud Security Monitor",
            "database": "connected",
            "statistics": stats
        }
    except Exception as e:
        return {
            "status": "degraded",
            "timestamp": datetime.utcnow().isoformat(),
            "service": "AI Cloud Security Monitor",
            "database": "error",
            "error": str(e)
        }


@router.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "AI Cloud Security Monitor API",
        "version": "1.0.0",
        "docs": "/docs"
    }
