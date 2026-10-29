import joblib

bundle = joblib.load("honeypot_app/ml/smartsoc_model.pkl")
print("Keys:", list(bundle.keys()))
print("Attack types:", list(bundle["classifier"].classes_))
print("Features:", bundle["feature_cols"])