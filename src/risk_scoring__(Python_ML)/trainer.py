from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib
from datetime import datetime

def train_model(data_path: str = 'data/synthetic_behavioral_data.csv') -> None:
    """
    Train and save the risk scoring model

    Args:
        data_path: Path to training data CSV
    """
    try:
        df = pd.read_csv(data_path)

        features = [
            'session_duration', 'tx_amount', 'geo_distance_delta',
            'device_change_freq', 'location_change_freq', 'txs_last_24h',
            'txs_last_7d', 'tx_hour', 'is_weekend', 'ip_risk_score'
        ]

        X = df[features]
        y = df['risk_flag_manual']

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )

        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )

        model.fit(X_train, y_train)

        # Save model with timestamp
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        base_path = Path(__file__).parent
        models_path = base_path / 'models'
        models_path.mkdir(exist_ok=True)

        # Save versioned model
        model_path = models_path / f'risk_model_v1_{timestamp}.pkl'
        joblib.dump(model, model_path)

        # Save as current model
        current_model_path = models_path / 'risk_model_v1.pkl'
        joblib.dump(model, current_model_path)

        print(f"Model saved to {current_model_path}")

        # Print model performance
        train_score = model.score(X_train, y_train)
        test_score = model.score(X_test, y_test)
        print(f"Train accuracy: {train_score:.4f}")
        print(f"Test accuracy: {test_score:.4f}")

    except Exception as e:
        print(f"Error training model: {e}")
        raise