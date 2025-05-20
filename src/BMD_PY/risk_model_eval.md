# Risk Model Evaluation Report

## Model Details
-**Model Type:** RandomForestClassifier
-**Number of estimators:** 100
-**Random state:** 42

## Data Overview
-**Total rows in dataset:** 51479
-**Training set rows:** 38609
-**Test set rows:** 12870
-**Target column:** `risk_flag_manual`
-**Class distribution in test set:**
  -**Class 0:** 95.83%
  -**Class 1:** 4.17%

## Evaluation Metrics on Test Set
-**ROC-AUC Score:** 1.0000
-**Precision Score:** 1.0000
-**Recall Score:** 1.0000

### Confusion Matrix
```
[[12333     0]
 [    0   537]]
```

### Classification Report
```
              precision    recall  f1-score   support

           0       1.00      1.00      1.00     12333
           1       1.00      1.00      1.00       537

    accuracy                           1.00     12870
   macro avg       1.00      1.00      1.00     12870
weighted avg       1.00      1.00      1.00     12870

```

## Feature Importance
The top 10 most important features are:
```
device_change_freq         0.171987
std_tx_amount_user         0.129922
location_change_freq       0.116489
tx_amount                  0.116381
ip_risk_score              0.113941
avg_tx_amount              0.068757
login_time_pattern_hour    0.049770
avg_tx_hour_user           0.045573
geo_distance_delta         0.044898
is_vpn                     0.029830
```

## Next Steps & Considerations
-**Advanced Preprocessing:** Further explore preprocessing techniques.
-**Feature Engineering:** Create new features.
-**Class Imbalance:** Address class imbalance in the dataset.
-**Model Hyperparameter Tuning:** Optimize model parameters.
-**Cross-validation:** Implement robust model evaluation.
-**Alternative Models:** Experiment with other models.
-**Deployment:** Prepare the model for API deployment.
