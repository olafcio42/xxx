from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List
import pandas as pd
import numpy as np

@dataclass
class TransactionFeatures:
    """Container for transaction features used in risk scoring"""
    session_duration: float
    tx_amount: float
    geo_distance_delta: float
    device_change_freq: float
    location_change_freq: float
    txs_last_24h: float
    txs_last_7d: float
    tx_hour: float
    is_weekend: float
    ip_risk_score: float

    def to_list(self) -> List[float]:
        """Convert features to list format for model input"""
        return [
            self.session_duration,
            self.tx_amount,
            self.geo_distance_delta,
            self.device_change_freq,
            self.location_change_freq,
            self.txs_last_24h,
            self.txs_last_7d,
            self.tx_hour,
            self.is_weekend,
            self.ip_risk_score
        ]