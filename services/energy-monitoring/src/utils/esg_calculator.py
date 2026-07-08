"""
ESG (Environmental, Social, Governance) Calculator
Calculates sustainability metrics from energy data
"""
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from ..models.energy import EnergyReading


class ESGCalculator:
    """Calculate ESG metrics from energy readings"""
    
    def __init__(self):
        self.co2_price_per_ton = 112.0  # USD per ton CO2
        self.min_renewable_pct = 35.0  # Minimum renewable percentage target
        self.carbon_intensity_threshold = 0.02  # kg CO2/kWh
    
    def calculate(self, reading: EnergyReading) -> Dict[str, Any]:
        """Calculate ESG metrics for a single energy reading"""
        
        # Basic calculations
        generation_mwh = reading.generation_mw * 0.0167  # Convert MW to MWh (assuming 1 hour interval)
        co2_emissions = generation_mwh * (reading.carbon_intensity or 0.0)
        
        # Get historical data for context (last 24 hours)
        # This would normally query the database
        historical_avg_renewable = self._get_historical_avg(reading.source_id, 'renewable_pct')
        historical_avg_co2 = self._get_historical_avg(reading.source_id, 'co2_intensity')
        
        # Calculate percentages and scores
        renewable_percentage = self._calculate_renewable_percentage(reading)
        
        # ESG scores (0-100 scale)
        esg_operational = self._calculate_operational_score(reading, renewable_percentage)
        esg_compliance = self._calculate_compliance_score(renewable_percentage)
        esg_impact = self._calculate_impact_score(co2_emissions)
        
        # Overall ESG score (weighted average)
        total_esg = (
            esg_operational * 0.4 +
            esg_compliance * 0.3 +
            esg_impact * 0.3
        )
        
        # Alert indicators
        co2_spike = False
        co2_increase_pct = 0.0
        if historical_avg_co2 and historical_avg_co2 > 0:
            co2_increase_pct = ((reading.carbon_intensity or 0) - historical_avg_co2) / historical_avg_co2
            co2_spike = co2_increase_pct > 0.5  # 50% increase triggers alert
        
        return {
            'co2_emissions': round(co2_emissions, 4),
            'renewable_percentage': round(renewable_percentage, 2),
            'total_generation': round(generation_mwh, 4),
            'energy_intensity': round(reading.carbon_intensity or 0, 6),
            'esg_operational_score': round(esg_operational, 2),
            'esg_compliance_score': round(esg_compliance, 2),
            'esg_impact_score': round(esg_impact, 2),
            'total_esg_score': round(total_esg, 2),
            'co2_spike': co2_spike,
            'co2_increase_pct': co2_increase_pct,
            'renewable_drop': renewable_percentage < self.min_renewable_pct,
            'renewable_target': self.min_renewable_pct
        }
    
    def _calculate_renewable_percentage(self, reading: EnergyReading) -> float:
        """Calculate renewable energy percentage based on source type"""
        # This would be enhanced with actual renewable capacity data
        renewable_types = ['solar', 'wind', 'hydro', 'geothermal', 'biomass']
        
        if reading.source and reading.source.energy_type.lower() in renewable_types:
            # Assume 100% renewable for known renewable sources
            # In production, this would use actual capacity mix data
            return 100.0
        else:
            # Non-renewable or unknown
            return 0.0
    
    def _calculate_operational_score(self, reading: EnergyReading, renewable_pct: float) -> float:
        """Calculate operational ESG score (40% weight)"""
        # Based on efficiency, data quality, and renewable percentage
        efficiency_score = reading.efficiency or 50.0  # Default to 50 if not provided
        quality_score = reading.data_quality or 80  # Default to 80 if not provided
        
        # Weighted score
        score = (
            renewable_pct / 100.0 * 0.5 +  # 50% renewable
            efficiency_score / 100.0 * 0.3 +  # 30% efficiency
            quality_score / 100.0 * 0.2  # 20% data quality
        ) * 100
        
        return min(score, 100.0)
    
    def _calculate_compliance_score(self, renewable_pct: float) -> float:
        """Calculate compliance ESG score (30% weight)"""
        # Based on meeting renewable targets
        if renewable_pct >= self.min_renewable_pct:
            return 100.0
        else:
            # Linear penalty below target
            return max(0.0, (renewable_pct / self.min_renewable_pct) * 100)
    
    def _calculate_impact_score(self, co2_emissions: float) -> float:
        """Calculate impact ESG score (30% weight)"""
        # Lower emissions = higher score
        # This would use industry benchmarks
        max_acceptable_emissions = 1000.0  # tons CO2 per period
        
        if co2_emissions <= 0:
            return 100.0
        elif co2_emissions >= max_acceptable_emissions:
            return 0.0
        else:
            return max(0.0, 100.0 - (co2_emissions / max_acceptable_emissions * 100))
    
    def _get_historical_avg(self, source_id: int, metric: str) -> Optional[float]:
        """Get historical average for a metric (placeholder)"""
        # In production, this would query the database
        # For now, return None to indicate no historical data
        return None