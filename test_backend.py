import pandas as pd
import traceback
from utils.ml_logic import evaluate_all_models, get_shap_explanations, get_decision_path, get_counterfactual, run_inference

status = {"selected_model": "Best Model"}

try:
    df = pd.read_csv("test.csv")
    print("Evaluating all models...")
    metrics = evaluate_all_models(df.copy())
    print("Metrics:", metrics)
    
    sample_df = df.sample(1)
    
    print("Running inference...")
    label, confidence, probs = run_inference(status["selected_model"], sample_df)
    print("Label:", label)
    
    print("Running SHAP...")
    shap_plots, top_features = get_shap_explanations(status["selected_model"], df)
    print("SHAP successful", "yes" if shap_plots else "no")
    
    print("Running logic...")
    decision_path = get_decision_path(status["selected_model"], sample_df)
    counterfactual = get_counterfactual(status["selected_model"], sample_df)
    print("Done")
except Exception as e:
    traceback.print_exc()
