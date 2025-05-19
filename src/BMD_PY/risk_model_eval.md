# Risk Model Evaluation Report

## Model Details
-**Model Type:** RandomForestClassifier
-**Number of estimators:** 100
-**Random state:** 42

## Data Overview
-**Total rows in dataset:** 50819
-**Training set rows:** 38114
-**Test set rows:** 12705
-**Target column:** `risk_flag_manual`
-**Class distribution in test set:**
  -**Class 0:** 95.76%
  -**Class 1:** 4.24%

## Evaluation Metrics on Test Set
-**ROC-AUC Score:** 1.0000
-**Precision Score:** 1.0000
-**Recall Score:** 1.0000

### Confusion Matrix
```
[[12166     0]
 [    0   539]]
```

### Classification Report
```
              precision    recall  f1-score   support

           0       1.00      1.00      1.00     12166
           1       1.00      1.00      1.00       539

    accuracy                           1.00     12705
   macro avg       1.00      1.00      1.00     12705
weighted avg       1.00      1.00      1.00     12705

```

## Feature Importance
The top 10 most important features are:
```
avg_tx_amount                0.131167
ip_risk_score                0.123343
device_change_freq           0.100454
tx_amount                    0.098125
std_tx_amount_user           0.088076
location_change_freq         0.086634
geo_distance_delta           0.065240
is_vpn                       0.062957
avg_tx_hour_user             0.046165
has_recent_password_reset    0.026757
```

## Next Steps & Considerations
-**Advanced Preprocessing:** Further explore preprocessing techniques.
-**Feature Engineering:** Create new features.
-**Class Imbalance:** Address class imbalance in the dataset.
-**Model Hyperparameter Tuning:** Optimize model parameters.
-**Cross-validation:** Implement robust model evaluation.
-**Alternative Models:** Experiment with other models.
-**Deployment:** Prepare the model for API deployment.
