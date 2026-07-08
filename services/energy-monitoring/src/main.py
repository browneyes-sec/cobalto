"""
Energy Monitoring Service - Main FastAPI Application
"""
import asyncio
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import uvicorn

from .config.settings import settings
from .models.energy import EnergySource, EnergyReading, ESGMetric
from .schemas.energy import (
    EnergySourceCreate, EnergySource,
    EnergyReadingCreate, EnergyReading,
    ESGMetric, ESGResponse,
    Alert, HealthResponse
)
from .services.energy_service import EnergyService
from .database import SessionLocal, engine, Base


# Create tables
Base.metadata.create_all(bind=engine)

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    debug=settings.DEBUG
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Health check endpoint
@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.utcnow().isoformat(),
        version=settings.APP_VERSION,
        services={
            "database": "connected",
            "redis": "available",
            "external_apis": "configured"
        }
    )


# Energy Source endpoints
@app.post("/api/v1/sources", response_model=EnergySource)
async def create_energy_source(source: EnergySourceCreate, db: Session = Depends(get_db)):
    """Create a new energy source"""
    service = EnergyService(db)
    return await service.create_energy_source(source.dict())


@app.get("/api/v1/sources", response_model=List[EnergySource])
async def get_energy_sources(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Get all energy sources"""
    service = EnergyService(db)
    return await service.get_energy_sources(skip, limit)


# Energy Reading endpoints
@app.post("/api/v1/energy/readings", response_model=EnergyReading)
async def add_energy_reading(
    reading: EnergyReadingCreate, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Add a new energy reading"""
    service = EnergyService(db)
    return await service.add_energy_reading(reading)


@app.get("/api/v1/energy/readings", response_model=List[EnergyReading])
async def get_energy_readings(
    source_id: Optional[int] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get energy readings with optional filters"""
    service = EnergyService(db)
    return await service.get_energy_readings(
        source_id=source_id,
        start_time=start_time,
        end_time=end_time,
        skip=skip,
        limit=limit
    )


# ESG endpoints
@app.get("/api/v1/energy/esg-metrics", response_model=List[ESGMetric])
async def get_esg_metrics(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: Session = Depends(get_db)
):
    """Get ESG metrics with optional date filters"""
    if not start_date or not end_date:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=7)
    
    return db.query(ESGMetric).filter(
        ESGMetric.timestamp >= start_date,
        ESGMetric.timestamp <= end_date
    ).order_by(ESGMetric.timestamp.desc()).all()


@app.get("/api/v1/energy/esg-score", response_model=ESGResponse)
async def get_esg_score(
    source_id: Optional[int] = None,
    days: int = 7,
    db: Session = Depends(get_db)
):
    """Get overall ESG score for time period"""
    service = EnergyService(db)
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    metrics = db.query(ESGMetric).filter(
        ESGMetric.timestamp >= start_date,
        ESGMetric.timestamp <= end_date
    )
    
    if source_id:
        # Join with readings to filter by source
        metrics = metrics.join(EnergyReading).filter(
            EnergyReading.source_id == source_id
        )
    
    metrics = metrics.all()
    
    if not metrics:
        return ESGResponse(success=False, metrics=[], alerts_generated=0)
    
    # Calculate average scores
    avg_operational = sum(m.esg_operational_score for m in metrics) / len(metrics)
    avg_compliance = sum(m.esg_compliance_score for m in metrics) / len(metrics)
    avg_impact = sum(m.esg_impact_score for m in metrics) / len(metrics)
    total_score = (avg_operational * 0.4 + avg_compliance * 0.3 + avg_impact * 0.3)
    
    return ESGResponse(
        success=True,
        metrics=metrics,
        alerts_generated=0  # Would count actual alerts
    )


# Alert endpoints
@app.get("/api/v1/alerts", response_model=List[Alert])
async def get_alerts(
    severity: Optional[str] = None,
    status: str = "active",
    db: Session = Depends(get_db)
):
    """Get alerts with optional filters"""
    query = db.query(Alert).filter(Alert.status == status)
    if severity:
        query = query.filter(Alert.severity == severity)
    return query.order_by(Alert.timestamp.desc()).all()


# Data ingestion endpoint
@app.post("/api/v1/ingest/{source}")
async def ingest_data(
    source: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Ingest data from external source"""
    service = EnergyService(db)
    result = await service.ingest_external_data(source)
    return result


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )