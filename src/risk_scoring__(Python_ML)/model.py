import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

class RiskScorer:
    """ML-based risk scoring for PQC Kyber transactions"""

    def __init__(self, model_path: str = 'models/risk_model_v1.pkl'):
        self.base_path = Path(__file__).parent
        self.model_path = self.base_path / model_path
        self.model = self._load_model()

    def _load_model(self) -> RandomForestClassifier:
        """Load or create the ML model"""
        self.model_path.parent.mkdir(exist_ok=True)
        try:
            return joblib.load(self.model_path)
        except FileNotFoundError:
            print(f"Model not found at {self.model_path}, initializing new model...")
            return self._initialize_model()

    def _initialize_model(self) -> RandomForestClassifier:
        """Initialize a new RandomForest model"""
        return RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )

    def predict_risk(self, features: List[float]) -> float:
        """
        Predict transaction risk score

        Args:
            features: [session_duration, tx_amount, geo_distance_delta,
                      device_change_freq, location_change_freq, txs_last_24h,
                      txs_last_7d, tx_hour, is_weekend, ip_risk_score]

        Returns:
            Risk score between 0 and 1
        """
        try:
            if len(features) != 10:
                raise ValueError(f"Expected 10 features, got {len(features)}")
            return float(self.model.predict_proba([features])[0][1])
        except Exception as e:
            print(f"Error in risk prediction: {e}")
            return 0.99  # High risk score on error