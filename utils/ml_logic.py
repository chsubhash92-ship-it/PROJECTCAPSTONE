import joblib
import tensorflow as tf
import os
import io
import base64
from PIL import Image
from fpdf import FPDF
import numpy as np
import pandas as pd
import shap
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import lime
import lime.lime_tabular
import config
from . import generate_plot_base64
from data_handler import preprocess_for_inference
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import tempfile

# Cache for models and explainers
MODELS = {}
EXPLAINERS = {}
LIME_EXPLAINERS = {}

def get_training_sample():
    """Loads a sample of training data for LIME initialization."""
    try:
        if os.path.exists(config.TRAIN_DATA):
            df = pd.read_csv(config.TRAIN_DATA, nrows=500)
            # Remove label if present
            for col in df.columns:
                if str(col).lower() == 'label':
                    df = df.drop(columns=[col])
                    break
            return preprocess_for_inference(df)
        else:
            # Fallback if training data not found
            return np.zeros((10, 78)) # Assuming 78 features
    except Exception as e:
        print(f"Error loading training sample: {e}")
        return np.zeros((10, 78))

def load_model_from_disk(model_name):
    """Loads the specified model from disk."""
    if model_name in MODELS:
        return MODELS[model_name]

    model_path = ""
    if model_name == "Random Forest":
        model_path = config.RF_MODEL_PATH
    elif model_name == "XGBoost":
        model_path = config.XGB_MODEL_PATH
    elif model_name == "CNN":
        model_path = os.path.join(config.MODEL_DIR, 'cnn_model.h5')
    elif model_name == "BiLSTM":
        model_path = os.path.join(config.MODEL_DIR, 'bilstm_model.h5')
    else:
        model_name = "Best Model"
        model_path = config.BEST_MODEL_PATH

    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found: {model_path}")

    if model_path.endswith('.h5'):
        model = tf.keras.models.load_model(model_path)
    else:
        model = joblib.load(model_path)
    
    MODELS[model_name] = model
    return model

def run_inference(model_name, data_df):
    """Runs prediction on valid DataFrame data."""
    model = load_model_from_disk(model_name)
    
    # Preprocess
    X = preprocess_for_inference(data_df)
    
    if "CNN" in model_name or "BiLSTM" in model_name:
        X_dl = X.reshape((X.shape[0], X.shape[1], 1))
        probs = model.predict(X_dl)
        pred_idx = np.argmax(probs, axis=1)[0]
        confidence = float(np.max(probs))
    else:
        pred_idx = model.predict(X)[0]
        probs = model.predict_proba(X)
        confidence = float(np.max(probs))
    
    label = config.LABELS.get(pred_idx, "UNKNOWN")
    
    # 2. Assign Threat Intelligence
    threat_intel = get_threat_intelligence(label, confidence)
    
    return label, confidence, probs[0], threat_intel

def get_threat_intelligence(label, confidence):
    """Assigns threat level and recommendation based on label and confidence."""
    level_key = 'NORMAL'
    if label != 'BENIGN':
        level_key = 'EMERGENCY' if confidence >= 0.85 else 'CRITICAL'
    
    level_data = config.THREAT_LEVELS.get(level_key)
    
    return {
        "level": level_data['label'],
        "color": level_data['color'],
        "icon": level_data['icon'],
        "recommendation": "Generating dynamic recommendation...",
        "patterns": []
    }

def get_behavioral_comparison(df, preds, sample_df=None):
    """
    Compares behavioral metrics between Normal (average) and a specific Attack sample.
    """
    try:
        # Define internal mapping for metric identification
        mapping = {
            'Flow Bytes/s': 'Bytes/sec',
            'Flow IAT Mean': 'Inter-arrival Time',
            'Flow Duration': 'Flow Duration',
            'Source IP': 'Src IP',
            'Source Port': 'Src Port'
        }
        
        # Calculate Normal benchmark (Dataset Mean)
        df_copy = df.copy()
        df_copy['is_attack'] = (preds != 0)
        
        # Handle IP-based metrics if possible
        ip_col = next((c for c in df.columns if 'ip' in str(c).lower()), None)
        
        results = {
            "labels": ["Average Normal", "Average Attack"],
            "metrics": []
        }
        
        # 1. Flow Metrics (Expanded with Units)
        flow_features = [
            ('Flow Bytes/s', 'Bytes/sec (B/s)'),
            ('Flow IAT Mean', 'inter_arrival_time (ms)'),
            ('Flow Duration', 'flow_duration (s)'),
            ('Packet Length Mean', 'packet_length_avg (B)'),
            ('Total Fwd Packets', 'Total Packets (fwd)'),
            ('Total Backward Packets', 'Total Packets (bwd)'),
            ('Flow Packets/s', 'Flow Rate (Pkt/s)')
        ]
        
        for f, display_name in flow_features:
            # Flexible matching: look for the keywords in column names
            search_term = f.lower()
            if 'flow ' in search_term:
                search_term = search_term.replace('flow ', '')
            
            col_name = next((c for c in df.columns if search_term in str(c).lower()), None)
            if col_name:
                # Normal and Attack are both Averages
                benign_val = float(df_copy[df_copy['is_attack'] == False][col_name].mean())
                attack_val = float(df_copy[df_copy['is_attack'] == True][col_name].mean())
                
                results["metrics"].append({
                    "name": display_name,
                    "normal": benign_val if not np.isnan(benign_val) else 0,
                    "attack": attack_val if not np.isnan(attack_val) else 0
                })
        
        # 2. IP distribution (Estimated if Source IP exists)
        if ip_col:
            # Normal is Average
            b_subset = df_copy[df_copy['is_attack'] == False]
            normal_ip_count = float(b_subset[ip_col].nunique())
            
            # Normal Avg requests per IP
            counts_b = b_subset[ip_col].value_counts()
            normal_req_avg = float(counts_b.mean() if not counts_b.empty else 0)
            
            # Attack is Average
            a_subset = df_copy[df_copy['is_attack'] == True]
            attack_ip_count = float(a_subset[ip_col].nunique())
            
            counts_a = a_subset[ip_col].value_counts()
            attack_req_avg = float(counts_a.mean() if not counts_a.empty else 0)

            results["metrics"].append({
                "name": "src_ip_count (unique)",
                "normal": normal_ip_count,
                "attack": attack_ip_count
            })
            results["metrics"].append({
                "name": "requests_per_ip (avg)",
                "normal": normal_req_avg,
                "attack": attack_req_avg
            })
            
        return results
    except Exception as e:
        print(f"Error in behavioral comparison: {e}")
        return {
            "labels": ["Normal", "Threat"],
            "metrics": [],
            "error": str(e)
        }

def calculate_alignment_score(metric_value, top_features, is_global=False):
    """
    Calculates alignment between ML model performance and XAI (feature importance).
    metric_value: can be confidence (single sample) or accuracy/avg_confidence (global).
    """
    if not top_features:
        return 0, "N/A"
    
    # Sum of top 3 SHAP values as a proxy for 'explanation strength'
    shap_sum = sum([f.get('SHAP', 0) for f in top_features[:3]])
    
    # Alignment heuristic
    score = (metric_value * 0.7) + (min(1.0, shap_sum * 2) * 0.3)
    
    prefix = "Global " if is_global else "Local "
    if score > 0.8:
        status = f"{prefix}Alignment High"
    elif score > 0.5:
        status = f"{prefix}Alignment Moderate"
    else:
        status = f"{prefix}Alignment Low"
        
    return float(score), status

def get_shap_explanations(model_name, original_df, sample_df=None):
    """Generates a dictionary of base64 SHAP plots (Waterfall, Bar, BeeSwarm, Dependence)."""
    try:
        model = load_model_from_disk(model_name)
        
        # 1. Prepare Data — keep samples small for speed
        bg_size = min(8, len(original_df))
        df_bg = original_df.sample(bg_size) if len(original_df) > bg_size else original_df
        X_bg = preprocess_for_inference(df_bg)
        
        # 15 samples for global plots
        sample_size = min(15, len(original_df))
        df_sample = original_df.sample(sample_size) if len(original_df) > sample_size else original_df
        X_summary = preprocess_for_inference(df_sample)
        
        if sample_df is not None:
            X_local = preprocess_for_inference(sample_df)
        else:
            X_local = X_summary[0:1]
        
        feature_names = [f"PC{i+1}" for i in range(X_summary.shape[1])]
        plots = {}
        
        # 2. Setup Explainer
        if "CNN" in model_name or "BiLSTM" in model_name:
            def predict_fn(x):
                return model.predict(x.reshape((x.shape[0], x.shape[1], 1)), verbose=0)
            explainer = shap.KernelExplainer(predict_fn, X_bg)
        elif model_name in ["Random Forest", "XGBoost"]:
            explainer = shap.TreeExplainer(model)
        else:
            explainer = shap.Explainer(model, X_bg)

        # 3. Local Explanation (Waterfall)
        sv_local = explainer(X_local)
        
        # Get pred_idx for current sample
        if "CNN" in model_name or "BiLSTM" in model_name:
            probs = model.predict(X_local.reshape((1, -1, 1)), verbose=0)
            pred_idx = np.argmax(probs, axis=1)[0]
        else:
            pred_idx = model.predict(X_local)[0]

        # Extract values for Waterfall
        if hasattr(sv_local, "values"):
            v = sv_local.values
            b = np.array(sv_local.base_values)
            if len(v.shape) == 3: # Multi-class
                v_local_flat = v[0, :, pred_idx]
                b_local_flat = b[0, pred_idx] if len(b.shape) == 2 else (b[pred_idx] if len(b.shape) == 1 else b)
            else:
                v_local_flat = v[0]
                base_val = b[0] if len(b.shape) > 0 else b
                b_local_flat = base_val
        elif isinstance(sv_local, list): # TreeExplainer list output
            v_local_flat = sv_local[pred_idx][0]
            b_local_flat = explainer.expected_value[pred_idx] if hasattr(explainer, "expected_value") else 0
        else:
            v_local_flat = sv_local[0]
            b_local_flat = explainer.expected_value if hasattr(explainer, "expected_value") else 0

        # Create Waterfall Plot
        try:
            fig, ax = plt.subplots(figsize=(10, 5))
            shap.waterfall_plot(shap.Explanation(
                values=v_local_flat,
                base_values=b_local_flat,
                data=X_local[0],
                feature_names=feature_names
            ), show=False)
            plt.tight_layout()
            plots['waterfall'] = generate_plot_base64(fig)
            plt.close(fig)
        except Exception as e:
            print(f"Waterfall error: {e}")

        # 4. Global Explanation (Multi-sample)
        top_features = []
        if len(original_df) > 1:
            try:
                # Reuse or recalculate global SHAP values
                if hasattr(explainer, "shap_values"):
                    sv_global = explainer.shap_values(X_summary)
                else:
                    sv_global = explainer(X_summary).values
                
                # Extract values for the specific class
                if isinstance(sv_global, list):
                    vals_global = sv_global[pred_idx]
                elif len(sv_global.shape) == 3:
                    vals_global = sv_global[:, :, pred_idx]
                else:
                    vals_global = sv_global

                # Feature Importance Table
                mean_abs_shap = np.mean(np.abs(vals_global), axis=0)
                top_indices = np.argsort(mean_abs_shap)[::-1][:10]
                for i, idx in enumerate(top_indices):
                    feat_name = feature_names[idx] if idx < len(feature_names) else f"PC{idx+1}"
                    top_features.append({"Rank": int(i+1), "Feature": feat_name, "SHAP": float(mean_abs_shap[idx])})

                # 2. Class-Wise Bar Plot
                try:
                    fig, _ = plt.subplots(figsize=(8, 4))
                    
                    # To show all classes in a stacked bar, we MUST pass the full sv_global
                    # rather than just vals_global (which is for pred_idx only).
                    # SHAP summary_plot with plot_type="bar" and a list/array of classes shows stacked importance.
                    
                    target_sv = sv_global
                    labels = list(config.LABELS.values())
                    
                    # SHAP summary_plot expects a list of arrays for multiclass
                    if not isinstance(target_sv, list) and len(target_sv.shape) == 3:
                        # Convert (N, F, C) -> list of [ (N, F), (N, F), ... ]
                        target_sv = [target_sv[:, :, i] for i in range(target_sv.shape[2])]
                    
                    # Try with labels first, fallback if TypeError occurs
                    labels = list(config.LABELS.values())
                    try:
                        shap.summary_plot(target_sv, X_summary, feature_names=feature_names, class_names=labels, plot_type="bar", show=False)
                    except TypeError:
                        # Fallback for older SHAP versions or unexpected arg signature
                        shap.summary_plot(target_sv, X_summary, feature_names=feature_names, plot_type="bar", show=False)
                        
                    plt.tight_layout()
                    plots['class_bar'] = generate_plot_base64(fig)
                    plt.close(fig)
                except Exception as e:
                    print(f"Bar plot error: {e}")

                # 3rd Plot: BeeSwarm
                try:
                    fig, _ = plt.subplots(figsize=(8, 4))
                    shap.summary_plot(vals_global, X_summary, feature_names=feature_names, show=False)
                    plt.tight_layout()
                    plots['beeswarm'] = generate_plot_base64(fig)
                    plt.close(fig)
                except Exception as e: print(f"Beeswarm error: {e}")

                # 4th Plot: Dependence
                try:
                    top_idx = top_indices[0]
                    fig, _ = plt.subplots(figsize=(8, 4))
                    shap.dependence_plot(top_idx, vals_global, X_summary, feature_names=feature_names, show=False)
                    plt.tight_layout()
                    plots['dependence'] = generate_plot_base64(fig)
                    plt.close(fig)
                except Exception as e: print(f"Dependence error: {e}")

            except Exception as e:
                print(f"Global SHAP error: {e}")

        return plots, top_features
    except Exception as e:
        import traceback
        print(f"SHAP main error: {traceback.format_exc()}")
        return None, [{"Error": str(e)}]

def get_lime_explanation(model_name, sample_df, original_df):
    """Generates a LIME explanation plot for a single sample."""
    try:
        model = load_model_from_disk(model_name)
        X = preprocess_for_inference(sample_df)
        
        # Initialize LIME explainer if not cached
        if model_name not in LIME_EXPLAINERS:
            training_data = get_training_sample()
            feature_names = [f"PC{i+1}" for i in range(training_data.shape[1])]
            class_names = list(config.LABELS.values())
            
            explainer = lime.lime_tabular.LimeTabularExplainer(
                training_data,
                feature_names=feature_names,
                class_names=class_names,
                mode='classification'
            )
            LIME_EXPLAINERS[model_name] = explainer
        else:
            explainer = LIME_EXPLAINERS[model_name]

        # Predict function wrapper
        if "CNN" in model_name or "BiLSTM" in model_name:
            def predict_fn(x):
                # Reshape for DL models (N, 78, 1)
                x_dl = x.reshape((x.shape[0], x.shape[1], 1))
                return model.predict(x_dl, verbose=0)
        else:
            predict_fn = model.predict_proba

        # Ensure X[0] matches the expected feature count of the explainer
        sample_x = X[0]
        if hasattr(explainer, 'feature_names') and len(sample_x) != len(explainer.feature_names):
            print(f"LIME Shape Mismatch: Data has {len(sample_x)} but explainer expects {len(explainer.feature_names)}")
            # Slice or pad to match (safety fallback)
            target_len = len(explainer.feature_names)
            if len(sample_x) > target_len:
                sample_x = sample_x[:target_len]
            else:
                sample_x = np.pad(sample_x, (0, target_len - len(sample_x)))

        # Generate explanation for the first sample
        exp = explainer.explain_instance(
            sample_x, 
            predict_fn, 
            num_features=10,
            top_labels=1
        )
        
        # Save plot to base64
        fig = exp.as_pyplot_figure()
        plt.tight_layout()
        plot_b64 = generate_plot_base64(fig)
        plt.close(fig)
        
        return plot_b64
    except Exception as e:
        import traceback
        print(f"LIME error: {traceback.format_exc()}")
        return None

def evaluate_all_models(data_df):
    """Evaluates all models on the provided DataFrame and returns metrics."""
    label_col = None
    for col in data_df.columns:
        if str(col).strip().lower() == 'label':
            label_col = col
            break
            
    if not label_col:
        return None
        
    label_map = {
        'BENIGN': 0, 'BENIGN': 0, 'ATTACK': 1,
        'DDOS': 1, 'DDoS': 1, 'DOS': 2, 'DoS': 2,
        'FTP-BRUTEFORCE': 2, 'SSH-BRUTEFORCE': 2,
        'PORT SCAN': 1, 'INFILTRATION': 1, 'HEARTBLEED': 2,
        'WEB ATTACK': 2, 'BOT': 1
    }
    y_true = data_df[label_col].map(lambda x: label_map.get(str(x).strip().upper(), 0)).values
    
    X = preprocess_for_inference(data_df)
    X_dl = X.reshape((X.shape[0], X.shape[1], 1))
    
    models_to_eval = ["Random Forest", "XGBoost", "CNN", "BiLSTM"]
    metrics = []
    
    for m in models_to_eval:
        try:
            model = load_model_from_disk(m)
            if "CNN" in m or "BiLSTM" in m:
                probs = model.predict(X_dl, verbose=0)
                y_pred = np.argmax(probs, axis=1)
            else:
                y_pred = model.predict(X)
                
            acc = float(accuracy_score(y_true, y_pred))
            p, r, f, _ = precision_recall_fscore_support(y_true, y_pred, average='weighted', zero_division=0)
            
            metrics.append({
                "Model": m,
                "Accuracy": acc,
                "Precision": float(p),
                "Recall": float(r),
                "F1": float(f)
            })
        except Exception as e:
            print(f"Error evaluating {m}: {e}")
            
    return metrics

def get_decision_path(model_name, data_df):
    """Extracts tree traverse decision path or surrogate path."""
    try:
        X = preprocess_for_inference(data_df)
        dt_path = os.path.join(config.MODEL_DIR, "decision_tree_model.pkl")
        if os.path.exists(dt_path):
            model = joblib.load(dt_path)
        else:
            model = load_model_from_disk(model_name)
            if "CNN" in model_name or "BiLSTM" in model_name:
                return "Neural Networks do not have a discrete decision path."
            
        if not hasattr(model, "decision_path"):
            return "Model does not support decision path extraction."
            
        node_indicator = model.decision_path(X)
        leaf_id = model.apply(X)
        feature = model.tree_.feature
        threshold = model.tree_.threshold

        path = []
        node_index = node_indicator.indices[node_indicator.indptr[0]:node_indicator.indptr[1]]
        for node_id in node_index:
            if leaf_id[0] == node_id:
                val = model.tree_.value[node_id]
                pred_class = config.LABELS.get(np.argmax(val), "UNKNOWN")
                path.append(f"Leaf Node -> Prediction: {pred_class}")
                continue

            if (X[0, feature[node_id]] <= threshold[node_id]):
                threshold_sign = "<="
            else:
                threshold_sign = ">"
            
            path.append(f"PC{feature[node_id]+1} ({X[0, feature[node_id]]:.2f}) {threshold_sign} {threshold[node_id]:.2f}")
            
        return " ->\n".join(path)
    except Exception as e:
        return f"Could not extract decision path: {e}"

def get_counterfactual(model_name, data_df):
    """Generates a randomized local counterfactual to flip the prediction."""
    try:
        model = load_model_from_disk(model_name)
        X = preprocess_for_inference(data_df)
        is_dl = "CNN" in model_name or "BiLSTM" in model_name
        
        def predict_fn(x_in):
            if is_dl:
                p = model.predict(x_in.reshape((x_in.shape[0], x_in.shape[1], 1)), verbose=0)
                return np.argmax(p, axis=1)[0]
            return model.predict(x_in)[0]

        original_pred = predict_fn(X)
        target_pred = 0 if original_pred != 0 else 1 # Flip to Benign if Malicious, or to Attack (any non-zero) if Benign
        target_name = "BENIGN" if target_pred == 0 else "MALICIOUS (Attack)"
        
        for i in range(100):
            # Use wider search for Benign to Malicious
            scale = 0.5 if original_pred != 0 else 1.5
            noise = np.random.normal(0, scale, X.shape)
            X_cf = X + noise
            cf_pred = predict_fn(X_cf)
            
            # Check if prediction flipped to the desired target
            is_flipped = (cf_pred == 0) if original_pred != 0 else (cf_pred != 0)
            
            if is_flipped:
                diff = X_cf - X
                top_indices = np.argsort(np.abs(diff[0]))[::-1][:3]
                
                changes = []
                for idx in top_indices:
                    val_diff = diff[0, idx]
                    direction = "Increase" if val_diff > 0 else "Decrease"
                    changes.append(f"- {direction} PC{idx+1} by {abs(val_diff):.2f}")
                    
                return f"To change classification to {target_name}, try:\n" + "\n".join(changes)
                
        return f"No simple counterfactual found to flip to {target_name} within local variance."
    except Exception as e:
        return f"Could not generate counterfactual: {e}"

def clean_pdf_text(text):
    """Utility to remove emojis and non-latin characters that crash standard FPDF."""
    if not text: return "N/A"
    # Remove emojis and non-ASCII chars
    import re
    cleaned = re.sub(r'[^\x00-\x7F]+', ' ', str(text))
    # Replace common AI symbols that might still cause issues
    return cleaned.replace('`', "'").replace('•', '-').strip()

def generate_pdf_report(data):
    """Generates a PDF bytes object from analysis data."""
    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        
        # Title
        pdf.set_font("Helvetica", "B", 20)
        pdf.cell(0, 10, "AI-Threat Diagnostic Report", ln=True, align="C")
        pdf.set_font("Helvetica", "", 10)
        
        # Add Current Timestamp
        import datetime
        report_time = data.get('timestamp') or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pdf.cell(0, 5, f"Report Generated: {report_time}", ln=True, align="C")
        pdf.ln(10)
        
        # 1. Executive Security Reflection (NEW)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_fill_color(240, 248, 255)
        pdf.cell(0, 10, " 1. AI Security Reflection", ln=True, fill=True)
        pdf.set_font("Helvetica", "", 10)
        reflection = data.get('llm_reflection') or data.get('llm_analysis') or "No reflection available."
        pdf.multi_cell(0, 6, clean_pdf_text(reflection), border='L')
        pdf.ln(8)

        # 2. Detailed Technical Remediation
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_fill_color(255, 245, 245)
        pdf.cell(0, 10, " 2. Technical Remediation Steps", ln=True, fill=True)
        
        intel = data.get('threat_intel', {})
        pdf.set_font("Helvetica", "B", 11)
        pdf.ln(2)
        
        # Clean recommendation text
        rec_text = intel.get('recommendation', 'Immediate technical remediation required.')
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 6, clean_pdf_text(rec_text), border='L')
        pdf.ln(5)
        
        if intel.get('patterns'):
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 8, "Observed Attack Patterns:", ln=True)
            pdf.set_font("Helvetica", "", 10)
            for p in intel['patterns']:
                pdf.multi_cell(0, 5, f"- {clean_pdf_text(p)}")
        pdf.ln(10)

        # 3. Model Prediction Summary
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_fill_color(248, 250, 252)
        pdf.cell(0, 10, " 3. Predictive Intelligence Summary", ln=True, fill=True)
        pdf.ln(2)
        
        # Add Severity Level and Prediction
        intel = data.get('threat_intel', {})
        pdf.set_font("Helvetica", "B", 12)
        severity = intel.get('level', 'N/A')
        pdf.cell(0, 10, f"STATUS: {severity}  |  THREAT: {data.get('label', 'UNKNOWN')}", ln=True)
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 8, f"Confidence Score: {data.get('confidence', 0)*100:.2f}%", ln=True)
        pdf.ln(5)
        
        # Dataset Overview (NEW)
        if data.get('dataset_meta'):
            meta = data['dataset_meta']
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(220, 53, 69) # Danger/Red for branding
            # Remove emojis for PDF compatibility
            pdf.cell(0, 10, f"DATASET OVERVIEW: {meta.get('shape', [0,0])[0]} Rows x {meta.get('shape', [0,0])[1]} Columns", ln=True)
            pdf.set_text_color(0, 0, 0)
            
            pdf.set_font("Courier", "", 8)
            # Take only first 1000 chars of info to avoid overflow
            info_txt = meta.get('info', '')[:1000] 
            pdf.multi_cell(0, 4, info_txt, border=1)
            pdf.ln(5)
            
            # Sub-table for Head(5)
            head_data = meta.get('head')
            if head_data and isinstance(head_data, list) and isinstance(head_data[0], dict):
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 8, "Snapshot (First 5 Rows - Selected Columns):", ln=True)
                pdf.set_font("Helvetica", "", 7)
                # Render only first 6 columns to fit the page
                cols = list(head_data[0].keys())[:6]
                col_width = 190 / max(1, len(cols))
                for c in cols:
                    pdf.cell(col_width, 6, str(c)[:15], border=1)
                pdf.ln()
                for h_row in head_data:
                    if isinstance(h_row, dict):
                        for c in cols:
                            pdf.cell(col_width, 6, str(h_row.get(c, ''))[:20], border=1)
                        pdf.ln()
            pdf.ln(5)
        
        # Full Scan Summary (NEW)
        if data.get('dataset_meta') and 'scan_summary' in data['dataset_meta']:
            summary = data['dataset_meta']['scan_summary']
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_text_color(255, 69, 0) # Orange-Red for summary
            pdf.cell(0, 10, "0. Full Dataset Analysis Summary", ln=True)
            pdf.set_text_color(0, 0, 0)
            
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(90, 8, "Metric", border=1, fill=False)
            pdf.cell(90, 8, "Value", border=1, fill=False)
            pdf.ln()
            
            pdf.set_font("Helvetica", "", 11)
            pdf.cell(90, 8, "Total Records Scanned", border=1)
            pdf.cell(90, 8, str(summary.get('total_rows', 0)), border=1)
            pdf.ln()
            pdf.cell(90, 8, "Threats Detected", border=1)
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(220, 53, 69) if summary.get('threat_found') else pdf.set_text_color(40, 167, 69)
            pdf.cell(90, 8, str(summary.get('threat_count', 0)), border=1)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 11)
            pdf.ln()
            
            # Breakdown sub-table
            if summary.get('breakdown'):
                pdf.ln(2)
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 8, "Detection Breakdown by Type:", ln=True)
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(90, 7, "Category", border=1)
                pdf.cell(90, 7, "Count", border=1)
                pdf.ln()
                pdf.set_font("Helvetica", "", 9)
                for label, count in summary['breakdown'].items():
                    pdf.cell(90, 7, label, border=1)
                    pdf.cell(90, 7, str(count), border=1)
                    pdf.ln()
            pdf.ln(5)

        
        # Model Metrics (REMOVED)

        # Top Features
        if data.get('top_features'):
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_text_color(0, 102, 204)
            pdf.cell(0, 10, "2. Feature Importance Correlation Matrix", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(20, 8, "Rank", border=1)
            pdf.cell(80, 8, "Feature", border=1)
            pdf.cell(40, 8, "Model Imp.", border=1)
            pdf.cell(40, 8, "SHAP Imp.", border=1)
            pdf.ln()
            pdf.set_font("Helvetica", "", 10)
            for f in data['top_features']:
                pdf.cell(20, 8, f"#{f.get('Rank', '?')}", border=1)
                pdf.cell(80, 8, f.get('Feature', 'N/A'), border=1)
                pdf.cell(40, 8, f"{f.get('ModelImp', 0):.4f}", border=1)
                pdf.cell(40, 8, f"{f.get('SHAP', 0):.4f}", border=1)
                pdf.ln()
            pdf.ln(5)

            pdf.ln(5)

        # Analyzed Traffic Snapshot (NEW)
        if data.get('data_snapshot'):
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_text_color(0, 102, 204)
            pdf.cell(0, 10, "3. Analyzed Traffic Snapshot (Top 5 Components)", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(80, 8, "Feature Component", border=1)
            pdf.cell(60, 8, "Value (PCA)", border=1)
            pdf.ln()
            pdf.set_font("Helvetica", "", 10)
            for item in data['data_snapshot']:
                pdf.cell(80, 8, item.get('Feature', 'N/A'), border=1)
                pdf.cell(60, 8, f"{item.get('Value', 0):.6f}", border=1)
                pdf.ln()
            pdf.ln(5)

        # Decision Path & Counterfactual
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(0, 102, 204)
        pdf.cell(0, 10, "4. Logic & Counterfactuals", ln=True)
        pdf.set_text_color(0, 0, 0)
        
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "Decision Path:", ln=True)
        pdf.set_font("Courier", "", 9)
        pdf.multi_cell(0, 5, data.get('decision_path', "N/A"))
        pdf.ln(5)
        
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "Counterfactual Scenario:", ln=True)
        pdf.set_font("Courier", "", 9)
        pdf.multi_cell(0, 5, data.get('counterfactual', "N/A"))
        pdf.ln(10)

        # Global Alignment (NEW)
        if data.get('threat_intel') and 'alignment_score' in data['threat_intel']:
            intel = data['threat_intel']
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 8, "Global Model vs XAI Alignment:", ln=True)
            pdf.set_font("Helvetica", "", 10)
            metric_name = "Dataset Accuracy" if intel.get('is_accuracy_based') else "Global Avg Confidence"
            pdf.cell(0, 6, f"- {metric_name}: {intel.get('global_metric_value', 0)*100:.2f}%", ln=True)
            pdf.cell(0, 6, f"- Global Explanation Strength (XAI): {intel.get('alignment_score', 0)*100:.2f}%", ln=True)
            pdf.cell(0, 6, f"- Alignment Verdict: {intel.get('alignment_status', 'N/A')}", ln=True)
            pdf.ln(5)

        # Gemini Analysis (NEW)
        if data.get('llm_analysis'):
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_text_color(220, 53, 69) # Danger Red for AI Alert
            pdf.cell(0, 10, "6. AI Security Reflection", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 10)
            
            # Sanitization: Force to latin-1 acceptable characters to avoid codec errors
            clean_analysis = str(data['llm_analysis']).encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 5, clean_analysis)
            pdf.ln(10)
        
        # Threat Summary Section
        pdf.set_font("Helvetica", "B", 13)
        threat_label = data.get('label', 'NORMAL')
        # Map icon/label safely without emojis
        status_text = f"ANALYSIS RESULT: {threat_label}"
        if threat_label != 'BENIGN':
            pdf.set_text_color(220, 53, 69) # Red for threats
        else:
            pdf.set_text_color(40, 167, 69) # Green for benign
            
        pdf.cell(0, 10, status_text, ln=True)
        pdf.set_text_color(0, 0, 0) # Reset color

        # SHAP Charts
        if data.get('shap_plots'):
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_text_color(0, 102, 204)
            pdf.cell(0, 10, "4. Explainable AI Visualizations", ln=True)
            pdf.set_text_color(0, 0, 0)
            
            for name, b64 in data['shap_plots'].items():
                if b64:
                    pdf.set_font("Helvetica", "B", 11)
                    pdf.cell(0, 10, f"SHAP Diagnostic: {name.replace('_', ' ').capitalize()}", ln=True)
                    try:
                        img_data = base64.b64decode(b64)
                        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
                            tmp.write(img_data)
                            tmp_path = tmp.name
                        pdf.image(tmp_path, w=180)
                        os.unlink(tmp_path)
                    except Exception as img_e:
                        pdf.cell(0, 5, f"Error rendering SHAP: {img_e}", ln=True)
                    pdf.ln(5)

            # LIME Plot
            if data.get('lime_plot'):
                pdf.add_page()
                pdf.set_font("Helvetica", "B", 14)
                pdf.set_text_color(0, 102, 204)
                pdf.cell(0, 10, "5. LIME Tabular Explanation", ln=True)
                pdf.set_text_color(0, 0, 0)
                try:
                    img_data = base64.b64decode(data['lime_plot'])
                    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
                        tmp.write(img_data)
                        tmp_path = tmp.name
                    pdf.image(tmp_path, w=180)
                    os.unlink(tmp_path)
                except Exception as img_e:
                    pdf.cell(0, 5, f"Error rendering LIME: {img_e}", ln=True)

        return pdf.output(dest='S').encode('latin-1')
    except Exception as e:
        import traceback
        print(f"PDF Gen Error: {e}")
        traceback.print_exc()
        return None
