import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import os

#Configuration
OUTPUT_FILE = 'synthetic_behavioral_data.csv'
NUM_NORMAL_USERS = 100
NUM_ANOMALOUS_USERS = 10
TRANSACTIONS_PER_NORMAL_USER = 50
TRANSACTIONS_PER_ANOMALOUS_USER = 20
START_DATE = datetime(2023, 1, 1)
END_DATE = datetime(2023, 12, 31)

#Data generation initialization
print(f"Starting synthetic behavioral data generation to file: {OUTPUT_FILE}")

data = []

#Generate data for normal users
user_id_counter = 1
tx_id_counter = 1

print(f"Generating data for {NUM_NORMAL_USERS} normal users...")
for _ in range(NUM_NORMAL_USERS):
    user_id = f'user_{user_id_counter}'
    user_id_counter += 1

    #Normal user pattern simulation
    avg_tx_amount = np.random.uniform(20, 500)
    std_tx_amount = avg_tx_amount * np.random.uniform(0.1, 0.3)
    avg_tx_hour = np.random.randint(8, 20)
    device_change_freq = np.random.uniform(0, 0.1)
    location_change_freq = np.random.uniform(0, 0.2)
    has_recent_password_reset = 0
    is_new_device = 0
    ip_risk_score = np.random.uniform(0, 0.1)
    country_mismatch = 0

    num_transactions = max(1, int(np.random.normal(TRANSACTIONS_PER_NORMAL_USER, 10)))

    for i in range(num_transactions):
        timestamp = START_DATE + timedelta(seconds=random.randint(0, int((END_DATE - START_DATE).total_seconds())))
        tx_hour = timestamp.hour
        is_weekend = 1 if timestamp.weekday() >= 5 else 0

        #Transaction features generation
        tx_amount = max(1, np.random.normal(avg_tx_amount, std_tx_amount))
        session_duration = max(10, int(np.random.normal(120, 60)))
        geo_distance_delta = max(0, np.random.normal(5, 10))
        login_time_pattern = f"{np.random.randint(0,23):02d}:{np.random.randint(0,59):02d}"
        txs_last_24h = int(np.random.normal(num_transactions / ((END_DATE - START_DATE).days / 365 * 24), 2))
        txs_last_7d = int(np.random.normal(num_transactions / ((END_DATE - START_DATE).days / 365 * 7), 5))

        #Categorical values generation
        currency = random.choice(['PLN', 'EUR', 'USD'])
        tx_type = random.choice(['purchase', 'transfer', 'withdrawal'])
        merchant_id = f'merchant_{random.randint(1, 100)}'
        tx_location = f'loc_{random.randint(1, 50)}'
        device_id = f'dev_{random.randint(1, 20)}'
        ip_address = f'192.168.1.{random.randint(1, 254)}'
        is_vpn = 0

        #Baseline anomaly score
        anomaly_score_baseline = np.random.uniform(0, 0.2)

        data.append([
            session_duration, login_time_pattern, avg_tx_amount, tx_hour, geo_distance_delta,
            user_id, tx_id_counter, timestamp, tx_amount, currency, tx_type, merchant_id,
            tx_location, device_id, ip_address, is_vpn, avg_tx_amount, std_tx_amount,
            avg_tx_hour, device_change_freq, location_change_freq, txs_last_24h, txs_last_7d,
            has_recent_password_reset, is_new_device, tx_hour, 0, anomaly_score_baseline,
            country_mismatch, is_weekend, ip_risk_score
        ])
        tx_id_counter += 1

#Generate data for anomalous users
print(f"Generating data for {NUM_ANOMALOUS_USERS} anomalous users...")
for _ in range(NUM_ANOMALOUS_USERS):
    user_id = f'user_{user_id_counter}'
    user_id_counter += 1

    #Anomalous user pattern simulation
    avg_tx_amount = np.random.uniform(1000, 10000)
    std_tx_amount = avg_tx_amount * np.random.uniform(0.5, 1.5)
    avg_tx_hour = np.random.choice([random.randint(0, 7), random.randint(21, 23)])
    device_change_freq = np.random.uniform(0.5, 1.0)
    location_change_freq = np.random.uniform(0.5, 1.0)
    has_recent_password_reset = random.choice([0, 0, 1])
    is_new_device = random.choice([0, 0, 1])
    ip_risk_score = np.random.uniform(0.5, 1.0)
    country_mismatch = random.choice([0, 0, 1])

    num_transactions = max(1, int(np.random.normal(TRANSACTIONS_PER_ANOMALOUS_USER, 15)))

    for i in range(num_transactions):
        timestamp = START_DATE + timedelta(seconds=random.randint(0, int((END_DATE - START_DATE).total_seconds())))
        tx_hour = timestamp.hour
        is_weekend = 1 if timestamp.weekday() >= 5 else 0

        #Anomalous transaction features
        tx_amount = max(1, np.random.normal(avg_tx_amount, std_tx_amount * 1.5))
        session_duration = max(5, int(np.random.normal(60, 40)))
        geo_distance_delta = max(100, np.random.normal(500, 300))
        login_time_pattern = f"{np.random.randint(0,23):02d}:{np.random.randint(0,59):02d}"
        txs_last_24h = int(np.random.normal(num_transactions / ((END_DATE - START_DATE).days / 365 * 24) * 5, 5))
        txs_last_7d = int(np.random.normal(num_transactions / ((END_DATE - START_DATE).days / 365 * 7) * 3, 10))

        #Anomalous categorical values
        currency = random.choice(['PLN', 'EUR', 'USD', 'GBP', 'JPY'])
        tx_type = random.choice(['purchase', 'transfer', 'withdrawal', 'online_payment', 'international_transfer'])
        merchant_id = f'merchant_{random.randint(101, 200)}'
        tx_location = f'loc_{random.randint(51, 100)}'
        device_id = f'dev_{random.randint(21, 40)}'
        ip_address = f'10.0.0.{random.randint(1, 254)}'
        is_vpn = random.choice([0, 1, 1])

        #Higher baseline anomaly score
        anomaly_score_baseline = np.random.uniform(0.5, 1.0)

        data.append([
            session_duration, login_time_pattern, avg_tx_amount, tx_hour, geo_distance_delta,
            user_id, tx_id_counter, timestamp, tx_amount, currency, tx_type, merchant_id,
            tx_location, device_id, ip_address, is_vpn, avg_tx_amount, std_tx_amount,
            avg_tx_hour, device_change_freq, location_change_freq, txs_last_24h, txs_last_7d,
            has_recent_password_reset, is_new_device, tx_hour, 1, anomaly_score_baseline,
            country_mismatch, is_weekend, ip_risk_score
        ])
        tx_id_counter += 1

#Column definitions
columns = [
    'session_duration',
    'login_time_pattern',
    'avg_tx_amount',
    'tx_time_of_day',
    'geo_distance_delta',
    'user_id',
    'tx_id',
    'timestamp',
    'tx_amount',
    'currency',
    'tx_type',
    'merchant_id',
    'tx_location',
    'device_id',
    'ip_address',
    'is_vpn',
    'avg_tx_amount_user',
    'std_tx_amount_user',
    'avg_tx_hour_user',
    'device_change_freq',
    'location_change_freq',
    'txs_last_24h',
    'txs_last_7d',
    'has_recent_password_reset',
    'is_new_device',
    'tx_hour',
    'risk_flag_manual',
    'anomaly_score_baseline',
    'country_mismatch',
    'is_weekend',
    'ip_risk_score'
]

#Create DataFrame
df = pd.DataFrame(data, columns=columns)

#Remove redundant column
df = df.drop(columns=['tx_time_of_day'])

#Save to CSV
print(f"\nSaving data to file: {OUTPUT_FILE}")
try:
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"File {OUTPUT_FILE} has been successfully generated.")
    print(f"Generated {df.shape[0]} rows of data.")
except Exception as e:
    print(f"Error occurred while saving CSV file: {e}")

print("\nData generation completed.")