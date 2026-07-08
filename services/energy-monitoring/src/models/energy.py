"""
Energy Monitoring Database Models
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

Base = declarative_base()


class EnergySource(Base):
    """Energy generation source (solar, wind, etc.)"""
    __tablename__ = "energy_sources"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    energy_type = Column(String(50), nullable=False)  # solar, wind, hydro, etc.
    location = Column(String(200))
    capacity_mw = Column(Float)
    longitude = Column(Float)
    latitude = Column(Float)
    installed_date = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), default="active")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    readings = relationship("EnergyReading", back_populates="source", cascade="all, delete-orphan")


class EnergyReading(Base):
    """Energy generation reading"""
    __tablename__ = "energy_readings"
    
    id = Column(Integer, primary_key=True, index=True)
    source_id = Column(Integer, ForeignKey("energy_sources.id"), nullable=False)
    reading_time = Column(DateTime, nullable=False, index=True)
    generation_mw = Column(Float, nullable=False)
    carbon_intensity = Column(Float)  # kg CO2/kWh
    efficiency = Column(Float)  # percentage
    temperature = Column(Float)  # degrees F or C
    humidity = Column(Float)  # percentage
    data_quality = Column(Integer)  # 0-100 score
    data_source = Column(String(50))  # external_api, sensor, etc.
    external_id = Column(String(100))  # ID from external system
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    source = relationship("EnergySource", back_populates="readings")
    esg_metrics = relationship("ESGMetric", back_populates="reading", cascade="all, delete-orphan")


class ESGMetric(Base):
    """ESG metrics calculated from energy readings"""
    __tablename__ = "esg_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    reading_id = Column(Integer, ForeignKey("energy_readings.id"), nullable=False)
    timestamp = Column(DateTime, nullable=False, index=True)
    co2_emissions = Column(Float)  # tons CO2
    renewable_percentage = Column(Float)  # percentage
    total_generation = Column(Float)  # MWh
    energy_intensity = Column(Float)  # CO2 per MWh
    esg_operational_score = Column(Float)  # 0-100
    esg_compliance_score = Column(Float)  # 0-100
    esg_impact_score = Column(Float)  # 0-100
    total_esg_score = Column(Float)  # 0-100
    assessment_date = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    reading = relationship("EnergyReading", back_populates="esg_metrics")


class Alert(Base):
    """ESG/energy alert"""
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)  # critical, warning, info
    title = Column(String(200), nullable=False)
    description = Column(Text)
    asset_id = Column(String(100))
    metric_value = Column(Float)
    threshold_value = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(100))
    acknowledged_at = Column(DateTime)
    status = Column(String(20), default="active")
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    """Audit log for ESG system actions"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    action = Column(String(100), nullable=False)
    user_id = Column(String(100), nullable=False)
    resource_type = Column(String(50))
    resource_id = Column(String(100))
    changes = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ip_address = Column(String(50))


class Ingestion(Base):
    """Track data ingestion from external sources"""
    __tablename__ = "ingestions"
    
    id = Column(Integer, primary_key=True, index=True)
    data_source = Column(String(100), nullable=False)
    reading_count = Column(Integer, default=0)
    success_count = Column(Integer, default=0)
    error_count = Column(Integer, default=0)
    last_successful_ingestion = Column(DateTime)
    current_status = Column(String(20), default="active")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# Association table for many-to-many relationship
energy_readings_tags = Table(
    'energy_readings_tags',
    Base.metadata,
    Column('reading_id', Integer, ForeignKey('energy_readings.id'), primary_key=True),
    Column('tag_id', Integer, ForeignKey('tags.id'), primary_key=True)
)


class Tag(Base):
    """Tags for categorizing energy readings"""
    __tablename__ = "tags"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(String(200))
    created_at = Column(DateTime, default=datetime.utcnow)