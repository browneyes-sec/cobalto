"""
Pydantic schemas for Energy Monitoring API
"""
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime
from typing import Optional, List


# Energy Source Schemas
class EnergySourceBase(BaseModel):
    """Base schema for energy source"""
    name: str = Field(..., min_length=1, max_length=100)
    energy_type: str = Field(..., min_length=1, max_length=50)
    location: Optional[str] = Field(None, max_length=200)
    capacity_mw: Optional[float] = Field(None, gt=0)
    longitude: Optional[float] = None
    latitude: Optional[float] = None


class EnergySourceCreate(EnergySourceBase):
    """Schema for creating energy source"""
    pass


class EnergySource(EnergySourceBase):
    """Schema for energy source response"""
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    installed_date: datetime
    status: str
    created_at: datetime
    updated_at: datetime


# Energy Reading Schemas
class EnergyReadingBase(BaseModel):
    """Base schema for energy reading"""
    source_id: int
    reading_time: datetime
    generation_mw: float = Field(..., ge=0)
    carbon_intensity: Optional[float] = Field(None, ge=0)
    efficiency: Optional[float] = Field(None, ge=0, le=100)
    temperature: Optional[float] = None
    humidity: Optional[float] = Field(None, ge=0, le=100)
    data_quality: Optional[int] = Field(None, ge=0, le=100)
    data_source: Optional[str] = None


class EnergyReadingCreate(EnergyReadingBase):
    """Schema for creating energy reading"""
    pass


class EnergyReading(EnergyReadingBase):
    """Schema for energy reading response"""
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    created_at: datetime


# ESG Metric Schemas
class ESGMetricBase(BaseModel):
    """Base schema for ESG metric"""
    reading_id: int
    timestamp: datetime
    co2_emissions: float
    renewable_percentage: float
    total_generation: float
    energy_intensity: float
    esg_operational_score: float
    esg_compliance_score: float
    esg_impact_score: float
    total_esg_score: float


class ESGMetricCreate(ESGMetricBase):
    """Schema for creating ESG metric"""
    pass


class ESGMetric(ESGMetricBase):
    """Schema for ESG metric response"""
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    assessment_date: datetime
    created_at: datetime


# Alert Schemas
class AlertBase(BaseModel):
    """Base schema for alert"""
    alert_type: str
    severity: str
    title: str
    description: Optional[str] = None
    asset_id: Optional[str] = None
    metric_value: Optional[float] = None
    threshold_value: Optional[float] = None


class AlertCreate(AlertBase):
    """Schema for creating alert"""
    pass


class Alert(AlertBase):
    """Schema for alert response"""
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    timestamp: datetime
    acknowledged: bool
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    status: str
    created_at: datetime


# Response Schemas
class EnergyDataResponse(BaseModel):
    """Response for energy data"""
    success: bool
    data: List[EnergyReading]
    total: int


class ESGResponse(BaseModel):
    """Response for ESG metrics"""
    success: bool
    metrics: ESGMetric
    alerts_generated: int


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: str
    version: str
    services: dict