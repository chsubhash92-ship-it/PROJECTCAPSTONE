/**
 * 🛡️ AI-Threat-Sentry Dashboard Logic v3.5
 * Synchronized with Diagnostic Grid UI
 */

document.addEventListener('DOMContentLoaded', async () => {
    // Top-level elements
    const clock = document.getElementById('clock');
    const modelSelect = document.getElementById('model-select');
    const analyzeBtn = document.getElementById('analyze-btn');
    const csvFile = document.getElementById('csv-file');
    const analysisResult = document.getElementById('analysis-result');
    const downloadPdfBtn = document.getElementById('download-pdf-btn');

    // Diagnostic Grid Containers
    const shapWaterfall = document.getElementById('shap-waterfall-container');
    const shapBar = document.getElementById('shap-bar-container');
    const limeContainer = document.getElementById('lime-container');
    const dataRule = document.getElementById('data-rule-container');
    const counterfactualContainer = document.getElementById('counterfactual-container');

    // State
    let isAnalyzing = false;
    let lastAnalysisData = null;
    let baselineData = null;

    // 1. Clock Initialization
    setInterval(() => {
        if (clock) clock.textContent = new Date().toLocaleTimeString();
    }, 1000);

    // 2. Fetch and Update Baseline Metrics
    const updateBaselineDisplay = (modelName) => {
        if (!baselineData) return;
        
        // Match the model name from the dropdown to the config keys
        const metrics = baselineData[modelName] || baselineData["Best Model"];
        if (!metrics) return;
        
        const updateText = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = (val * 100).toFixed(4) + '%';
        };

        updateText('base-acc', metrics.Accuracy);
        updateText('base-prc', metrics.Precision);
        updateText('base-rec', metrics.Recall);
        updateText('base-f1', metrics.F1);
        updateText('base-auc', metrics.AUC);
    };

    // Load initial baseline data
    try {
        const res = await fetch('/api/baseline_metrics');
        if (res.ok) {
            baselineData = await res.json();
            updateBaselineDisplay(modelSelect.value);
        }
    } catch (e) {
        console.error("Critical Error: Failed to load baseline metrics.", e);
    }

    // 3. Model Selection Handler
    modelSelect.addEventListener('change', async () => {
        const modelName = modelSelect.value;
        updateBaselineDisplay(modelName);
        
        try {
            await fetch('/api/select_model', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ model_name: modelName })
            });
        } catch (e) {
            console.error("Endpoint Error: /api/select_model failed.", e);
        }
    });

    // 4. CSV Diagnostic Handler
    analyzeBtn.addEventListener('click', async () => {
        if (isAnalyzing || !csvFile.files[0]) {
            if (!csvFile.files[0]) alert("Please select a network traffic CSV file.");
            return;
        }

        const formData = new FormData();
        formData.append('file', csvFile.files[0]);

        isAnalyzing = true;
        analyzeBtn.disabled = true;
        analyzeBtn.innerHTML = '<span class="status-dot pulse"></span> Analyzing...';
        
        // Reset and show loading states
        if (analysisResult) analysisResult.innerHTML = '<div class="result-box processing">📡 Initializing Neural Engine...</div>';
        
        const loaderHtml = '<div class="loading-wrapper"><div class="spinner"></div><p>Computing Explainability Matrix...</p></div>';
        if (shapWaterfall) shapWaterfall.innerHTML = loaderHtml;
        if (shapBar) shapBar.innerHTML = loaderHtml;
        if (limeContainer) limeContainer.innerHTML = loaderHtml;
        if (dataRule) dataRule.innerHTML = '<p class="loading-text">Extracting logic rules...</p>';
        if (counterfactualContainer) counterfactualContainer.innerHTML = '<p class="loading-text">Simulating alternative scenarios...</p>';
        
        if (downloadPdfBtn) downloadPdfBtn.style.display = 'none';

        try {
            const res = await fetch('/api/analyze_csv', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();
            console.log("📌 Diagnostic Data Received [Backend Version: " + (data.version || "Unknown") + "]:", data);

            if (data.error) {
                analysisResult.innerHTML = `<div class="result-box danger">🚨 ERROR: ${data.error}</div>`;
                return;
            }

            // Update Summary Result
            if (data.dataset_meta && data.dataset_meta.scan_summary) {
                const summary = data.dataset_meta.scan_summary;
                analysisResult.innerHTML = `
                    <div class="result-box ${summary.threat_found ? 'danger' : 'success'} animate-fade">
                        <span class="status-msg">${summary.threat_found ? '⚠️ THREATS DETECTED' : '✅ SYSTEM VULNERABILITY: LOW'}</span>
                        <span class="detail-msg">Target Sample: <strong>${data.label}</strong> (Confidence: ${(data.confidence*100).toFixed(2)}%)</span>
                    </div>
                `;
            }

            lastAnalysisData = data;
            if (downloadPdfBtn) downloadPdfBtn.style.display = 'inline-flex';

            // Populate Visual Panels
            const setPlot = (container, plotData, altText) => {
                if (container && plotData) {
                    container.innerHTML = `<img src="data:image/png;base64,${plotData}" class="diagnostic-img" alt="${altText}">`;
                } else if (container) {
                    container.innerHTML = '<p class="hint">Visualization data unavailable for this sample.</p>';
                }
            };

            setPlot(shapWaterfall, data.shap_plots?.waterfall, "SHAP Waterfall");
            setPlot(shapBar, data.shap_plots?.class_bar, "Class Impact");
            setPlot(limeContainer, data.lime_plot, "LIME Tabular");

            if (dataRule) dataRule.textContent = data.decision_path || "Model utilized deep heuristic branching - specific rule not found.";
            if (counterfactualContainer) counterfactualContainer.textContent = data.counterfactual || "No minimal feature changes could alter this high-confidence prediction.";

        } catch (e) {
            console.error("Network Error:", e);
            analysisResult.innerHTML = '<div class="result-box danger">🔌 DISCONNECTED: Check backend status.</div>';
        } finally {
            isAnalyzing = false;
            analyzeBtn.disabled = false;
            analyzeBtn.textContent = "Run Diagnostics";
        }
    });

    // 5. PDF Generation Handler
    downloadPdfBtn.addEventListener('click', async () => {
        if (!lastAnalysisData) return;
        downloadPdfBtn.textContent = "Generating PDF...";
        downloadPdfBtn.disabled = true;

        try {
            const response = await fetch('/api/download_pdf', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(lastAnalysisData)
            });
            
            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                a.download = `CyberSentinel_Report_${new Date().getTime()}.pdf`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
            } else {
                alert("Generation error. Please check backend logs.");
            }
        } catch (e) {
            console.error("PDF Fail:", e);
        } finally {
            downloadPdfBtn.textContent = "Export PDF";
            downloadPdfBtn.disabled = false;
        }
    });

    // File input UX
    csvFile.addEventListener('change', (e) => {
        const fileName = e.target.files[0]?.name || "Choose CSV";
        document.querySelector('label[for="csv-file"]').textContent = fileName.length > 20 ? fileName.substring(0, 17) + "..." : fileName;
    });
});
