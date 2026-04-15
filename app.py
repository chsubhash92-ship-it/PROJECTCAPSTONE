import os
import time
import threading
import pandas as pd
import io
from flask import Flask, render_template, jsonify, request, send_file
import config

from intrusion_detector import update_selected_model
from utils.ml_logic import run_inference, get_shap_explanations

app = Flask(__name__)

# System Status
status = {
    "selected_model": "Best Model",
    "baseline_metrics": config.BASELINE_METRICS
}

@app.route('/')
def index():
    return render_template('index.html', model_names=["Best Model", "Random Forest", "XGBoost", "CNN", "BiLSTM"])

@app.route('/api/baseline_metrics', methods=['GET'])
def get_baseline_metrics():
    return jsonify(config.BASELINE_METRICS)

@app.route('/api/select_model', methods=['POST'])
def select_model():
    model_name = request.json.get('model_name', "Best Model")
    status["selected_model"] = model_name
    update_selected_model(model_name)
    return jsonify({"status": "SUCCESS", "current_model": model_name})

@app.route('/api/analyze_csv', methods=['POST'])
def analyze_csv():
    """Analyzes a single row or chunk of traffic from CSV."""
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    try:
        df = pd.read_csv(file)
        
        from utils.ml_logic import (
            get_shap_explanations, 
            get_lime_explanation, 
            get_decision_path, 
            get_counterfactual,
            run_inference,
            load_model_from_disk,
            evaluate_all_models
        )
        from data_handler import preprocess_for_inference
        import numpy as np

        
        # Multi-row inference logic
        model_name = status["selected_model"]
        X_full = preprocess_for_inference(df.copy())
        model = load_model_from_disk(model_name)
        
        if "CNN" in model_name or "BiLSTM" in model_name:
            X_full_dl = X_full.reshape((X_full.shape[0], X_full.shape[1], 1))
            probs_full = model.predict(X_full_dl, verbose=0)
            preds_full = np.argmax(probs_full, axis=1)
        else:
            preds_full = model.predict(X_full)
            probs_full = model.predict_proba(X_full)
            
        # Global metric calculation (FIXED NaN Issue)
        max_probs = np.max(probs_full, axis=1)
        global_avg_confidence = float(np.nanmean(max_probs)) if len(max_probs) > 0 else 0.0
        
        # Accuracy calculation if label present
        global_accuracy = None
        label_col = None
        for col in df.columns:
            if str(col).strip().lower() == 'label':
                label_col = col; break
        
        if label_col:
            from sklearn.metrics import accuracy_score
            label_map = {'BENIGN': 0, 'BENIGN': 0, 'ATTACK': 1, 'DDOS': 1, 'DDoS': 1, 'DOS': 2, 'DoS': 2}
            y_true = df[label_col].map(lambda x: label_map.get(str(x).strip().upper(), 0)).values
            global_accuracy = float(accuracy_score(y_true, preds_full))

        total_rows = len(df)
        unique_preds, counts = np.unique(preds_full, return_counts=True)
        threat_summary = {config.LABELS.get(int(p), "UNKNOWN"): int(c) for p, c in zip(unique_preds, counts)}
        
        malicious_indices = np.where(preds_full != 0)[0]
        is_threat_found = len(malicious_indices) > 0
        
        # Selection logic for XAI focus - now truly random
        if is_threat_found:
            sample_idx = int(np.random.choice(malicious_indices))
            sample_df = df.iloc[[sample_idx]].copy()
        else:
            sample_df = df.sample(1).copy()
            sample_idx = sample_df.index[0]

        # Dominant Threat Detection (NEW - reflects full dataset)
        from collections import Counter
        threat_counts = Counter(preds_full)
        # Find most common non-benign threat
        malicious_preds = [p for p in preds_full if p != 0]
        if malicious_preds:
            dominant_idx = Counter(malicious_preds).most_common(1)[0][0]
            dominant_label = config.LABELS.get(dominant_idx, "UNKNOWN")
            # Calculate avg confidence specifically for the dominant threat
            dominant_mask = (preds_full == dominant_idx)
            dominant_conf = float(np.nanmean(max_probs[dominant_mask]))
        else:
            dominant_label = "BENIGN"
            dominant_conf = global_avg_confidence

        # Run Global Threat Intelligence based on Dominant Class
        from utils.ml_logic import get_threat_intelligence
        threat_intel = get_threat_intelligence(dominant_label, dominant_conf)

        # Run Specific Inference/XAI (for visualization sample)
        label, confidence, probs, _ = run_inference(model_name, sample_df)
        shap_plots, top_features = get_shap_explanations(model_name, df, sample_df=sample_df)
        
        # Behavioral Comparison Analysis (NEW)
        from utils.ml_logic import get_behavioral_comparison
        behavioral_data = get_behavioral_comparison(df, preds_full, sample_df=sample_df)
        
        # Calculate Global XAI Alignment Score
        from utils.ml_logic import calculate_alignment_score
        alignment_score, alignment_status = calculate_alignment_score(
            global_accuracy if global_accuracy is not None else global_avg_confidence, 
            top_features,
            is_global=True
        )
        threat_intel["alignment_score"] = alignment_score
        threat_intel["alignment_status"] = alignment_status
        threat_intel["is_accuracy_based"] = (global_accuracy is not None)
        threat_intel["global_metric_value"] = global_accuracy if global_accuracy is not None else global_avg_confidence
        # Diagnostic explanations (Wrapped in safety blocks)
        try:
            lime_plot = get_lime_explanation(model_name, sample_df, df)
        except Exception as e:
            print(f"LIME error: {e}")
            lime_plot = None
            
        try:
            decision_path = get_decision_path(model_name, sample_df)
        except Exception as e:
            print(f"Decision Path error: {e}")
            decision_path = "N/A"
            
        try:
            counterfactual = get_counterfactual(model_name, sample_df)
        except Exception as e:
            print(f"Counterfactual error: {e}")
            counterfactual = "N/A"
        
        # Dataset summary metadata
        dataset_meta = {
            "shape": list(df.shape),
            "scan_summary": {
                "total_rows": total_rows,
                "threat_found": is_threat_found,
                "threat_count": int(np.sum(preds_full != 0)),
                "breakdown": threat_summary
            }
        }
        
        data_snapshot = [{"Feature": f"PC{i+1}", "Value": float(sample_df.values[0, i])} for i in range(min(5, sample_df.shape[1]))]
        
        # Gemini Analysis Integration (NEW dynamic intelligence)
        from utils.llm_helper import generate_security_analysis, generate_security_reflection
        
        # 1. Technical Analysis (Remediation + Patterns)
        llm_result = generate_security_analysis({
            "label": label,
            "confidence": confidence,
            "top_features": [f["Feature"] for f in top_features]
        })
        
        # 2. Executive Reflection (100-word concise summary)
        llm_reflection = generate_security_reflection({
            "label": label,
            "confidence": confidence,
            "top_features": [f["Feature"] for f in top_features]
        })
        
        # Construct final threat intelligence object with tiered severity based on confidence
        if not is_threat_found:
            threat_level = "Normal"
            threat_icon = "✅"
            threat_color = "#10b981"
            rec_text = "Maintain standard monitoring."
        else:
            # Tiered logic based on Confidence
            if dominant_conf < 0.80:
                threat_level = "Normal"
                threat_icon = "✅"
                threat_color = "#10b981"
                rec_text = "Standard detection observed. Normal operations."
            elif dominant_conf <= 0.90:
                threat_level = "Critical"
                threat_icon = "⚠️"
                threat_color = "#f59e0b"
                rec_text = "Critical security incident detected. High priority review required."
            else:
                threat_level = "Emergency"
                threat_icon = "🚨"
                threat_color = "#ef4444"
                rec_text = "Immediate technical remediation required."

        threat_intel = {
            "level": threat_level,
            "icon": threat_icon,
            "color": threat_color,
            "recommendation": rec_text,
            "patterns": [],
            "alignment_score": 1.0,
            "alignment_status": "Verified"
        }

        # Merge LLM results if available
        if isinstance(llm_result, dict) and not llm_result.get('error'):
            if llm_result.get('recommendation'):
                threat_intel["recommendation"] = llm_result['recommendation']
            if llm_result.get('patterns'):
                threat_intel["patterns"] = llm_result['patterns']
        elif isinstance(llm_result, str):
            threat_intel["recommendation"] = llm_result

        return jsonify({
            "label": label,
            "confidence": confidence,
            "probs": probs.tolist(),
            "shap_plots": shap_plots,
            "lime_plot": lime_plot,
            "decision_path": decision_path,
            "counterfactual": counterfactual,
            "top_features": top_features,
            "data_snapshot": data_snapshot,
            "dataset_meta": dataset_meta,
            "llm_analysis": llm_result.get('assessment', '') if isinstance(llm_result, dict) else str(llm_result),
            "llm_reflection": llm_reflection.get('assessment', str(llm_reflection)),
            "threat_intel": threat_intel,
            "behavioral_comparison": behavioral_data,
            "version": "v2.6.0-advanced"
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/download_pdf', methods=['POST'])
def download_pdf():
    try:
        data = request.json
        from utils.ml_logic import generate_pdf_report
        pdf_content = generate_pdf_report(data)
        
        if pdf_content:
            return send_file(
                io.BytesIO(pdf_content),
                mimetype='application/pdf',
                as_attachment=True,
                download_name='AI-Threat_Analysis.pdf'
            )
        else:
            return jsonify({"error": "Failed to generate PDF"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", config.PORT))
    app.run(host="0.0.0.0", port=port, debug=config.DEBUG)
