"""
Energy Service - Core business logic for energy data management
"""
import asyncio
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
from ..models.energy import EnergySource, EnergyReading, ESGMetric, Alert
from ..schemas.energy import EnergyReadingCreate, ESGMetricCreate
from ..utils.esg_calculator import ESGCalculator
from ..clients.external_energy_client import ExternalEnergyClient


class EnergyService:
    """Core energy data management service"""
    
    def __init__(self, db: Session):
        self.db = db
        self.esg_calculator = ESGCalculator()
        self.external_client = ExternalEnergyClient()
    
    async def create_energy_source(self, source_data: Dict[str, Any]) -> EnergySource:
        """Create a new energy source"""
        source = EnergySource(**source_data)
        self.db.add(source)
        await self.db.commit()
        await self.db.refresh(source)
        return source
    
    async def get_energy_source(self, source_id: int) -> Optional[EnergySource]:
        """Get energy source by ID"""
        return self.db.query(EnergySource).filter(EnergySource.id == source_id).first()
    
    async def get_energy_sources(self, skip: int = 0, limit: int = 100) -> List[EnergySource]:
        """Get all energy sources with pagination"""
        return self.db.query(EnergySource).offset(skip).limit(limit).all()
    
    async def add_energy_reading(self, reading_data: EnergyReadingCreate) -> EnergyReading:
        """Add a new energy reading"""
        reading = EnergyReading(**reading_data.dict())
        self.db.add(reading)
        await self.db.commit()
        await self.db.refresh(reading)
        
        # Calculate ESG metrics
        await self.calculate_and_store_esg_metrics(reading.id)
        
        return reading
    
    async def get_energy_readings(
        self, 
        source_id: Optional[int] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[EnergyReading]:
        """Get energy readings with optional filters"""
        query = self.db.query(EnergyReading)
        
        if source_id:
            query = query.filter(EnergyReading.source_id == source_id)
        if start_time:
            query = query.filter(EnergyReading.reading_time >= start_time)
        if end_time:
            query = query.filter(EnergyReading.reading_time <= end_time)
            
        return query.order_by(EnergyReading.reading_time.desc()).offset(skip).limit(limit).all()
    
    async def calculate_and_store_esg_metrics(self, reading_id: int) -> ESGMetric:
        """Calculate ESG metrics for a reading and store them"""
        reading = self.db.query(EnergyReading).filter(EnergyReading.id == reading_id).first()
        if not reading:
            raise ValueError(f"Reading {reading_id} not found")
        
        # Calculate ESG metrics
        esg_data = self.esg_calculator.calculate(reading)
        
        # Store metrics
        esg_metric = ESGMetric(
            reading_id=reading_id,
            timestamp=reading.reading_time,
            co2_emissions=esg_data['co2_emissions'],
            renewable_percentage=esg_data['renewable_percentage'],
            total_generation=esg_data['total_generation'],
            energy_intensity=esg_data['energy_intensity'],
            esg_operational_score=esg_data['esg_operational_score'],
            esg_compliance_score=esg_data['esg_compliance_score'],
            esg_impact_score=esg_data['esg_impact_score'],
            total_esg_score=esg_data['total_esg_score'],
            assessment_date=datetime.utcnow().date()
        )
        
        self.db.add(esg_metric)
        await self.db.commit()
        await self.db.refresh(esg_metric)
        
        # Check for alerts
        await self.check_and_create_alerts(reading, esg_data)
        
        return esg_metric
    
    async def check_and_create_alerts(self, reading: EnergyReading, esg_data: Dict) -> List[Alert]:
        """Check if reading triggers any alerts"""
        alerts = []
        
        # CO2 spike alert
        if esg_data.get('co2_spike', False):
            alert = Alert(
                alert_type="co2_spike",
                severity="critical",
                title="CO2 Emissions Spike Detected",
                description=f"CO2 emissions increased by {esg_data.get('co2_increase_pct', 0):.1f}% above threshold",
                asset_id=str(reading.source_id),
                metric_value=esg_data.get('co2_emissions', 0),
                threshold_value=esg_data.get('co2_threshold', 0),
                timestamp=datetime.utcnow()
            )
            self.db.add(alert)
            alerts.append(alert)
        
        # Renewable drop alert
        if esg_data.get('renewable_drop', False):
            alert = Alert(
                alert_type="renewable_drop",
                severity="warning",
                title="Renewable Energy Percentage Dropped",
                description=f"Renewable percentage dropped to {esg_data.get('renewable_percentage', 0):.1f}% below target",
                asset_id=str(reading.source_id),
                metric_value=esg_data.get('renewable_percentage', 0),
                threshold_value=esg_data.get('renewable_target', 35.0),
                timestamp=datetime.utcnow()
            )
            self.db.add(alert)
            alerts.append(alert)
        
        if alerts:
            await self.db.commit()
            for alert in alerts:
                await self.db.refresh(alert)
        
        return alerts
    
    async def ingest_external_data(self, source: str) -> Dict[str, Any]:
        """Ingest data from external energy API"""
        try:
            data = await self.external_client.fetch_data(source)
            success_count = 0
            error_count = 0
            
            for reading_data in data:
                try:
                    await self.add_energy_reading(reading_data)
                    success_count += 1
                except Exception as e:
                    error_count += 1
                    print(f"Error ingesting reading: {e}")
            
            return {
                "source": source,
                "total": len(data),
                "success": success_count,
                "errors": error_count,
                "status": "completed"
            }
        except Exception as e:
            return {
                "source": source,
                "error": str(e),
                "status": "failed"
            }