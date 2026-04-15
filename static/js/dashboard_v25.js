/**
 * AI-Threat-Sentry | dashboard_v25.js
 * FRESH FILE - bypasses browser cache
 */

document.addEventListener('DOMContentLoaded', async () => {

    // DOM References
    const clock          = document.getElementById('clock');
    const modelSelect    = document.getElementById('model-select');
    const analyzeBtn     = document.getElementById('analyze-btn');
    const csvFile        = document.getElementById('csv-file');
    const fileLabel      = document.getElementById('file-label');
    const analysisResult = document.getElementById('analysis-result');
    const downloadPdfBtn = document.getElementById('download-pdf-btn');

    // Diagnostic containers
    const predSummary  = document.getElementById('prediction-summary-container');
    const featContrib  = document.getElementById('feature-contribution-container');
    const shapBeeswarm = document.getElementById('shap-beeswarm-container');
    const shapWaterfall= document.getElementById('shap-waterfall-container');
    const shapBar      = document.getElementById('shap-bar-container');
    const shapSummary  = document.getElementById('lime-container');  // SHAP summary slot
    const dataRule     = document.getElementById('data-rule-container');
    const cfContainer  = document.getElementById('counterfactual-container');
    const scanSummary  = document.getElementById('scan-summary-container');
    const llmContainer = document.getElementById('llm-analysis-container');
    const threatIntelContainer = document.getElementById('threat-intel-container');
    const threatBadgeContainer = document.getElementById('threat-badge-container');
    const alignmentContainer   = document.getElementById('alignment-container');
    const behavioralContainer  = document.getElementById('behavioral-container');

    let isAnalyzing = false;
    let lastData    = null;
    let baselineData= null;
    let behavioralChartObj = null;

    console.log('dashboard_v25.js loaded OK');

    // Clock
    const updateClock = () => { if (clock) clock.textContent = new Date().toLocaleTimeString(); };
    updateClock();
    setInterval(updateClock, 1000);

    // Baseline banner
    const updateBaselineBanner = (modelName) => {
        if (!baselineData) return;
        const m = baselineData[modelName] || baselineData['Best Model'];
        if (!m) return;
        const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = (val * 100).toFixed(2) + '%'; };
        set('base-acc', m.Accuracy);
        set('base-prc', m.Precision);
        set('base-rec', m.Recall);
        set('base-f1',  m.F1);
        set('base-auc', m.AUC);
    };

    try {
        const res = await fetch('/api/baseline_metrics');
        baselineData = await res.json();
        updateBaselineBanner(modelSelect ? modelSelect.value : 'Best Model');
    } catch (e) { console.error('Baseline metrics error:', e); }

    if (modelSelect) {
        modelSelect.addEventListener('change', async () => {
            updateBaselineBanner(modelSelect.value);
            try {
                await fetch('/api/select_model', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ model_name: modelSelect.value })
                });
            } catch (e) { console.error('Model select failed:', e); }
        });
    }

    // View Switching Logic
    const navItems = document.querySelectorAll('.nav-item');
    const views    = document.querySelectorAll('.view-content');

    const switchView = (viewId) => {
        // Update Nav
        navItems.forEach(nav => {
            if (nav.getAttribute('data-view') === viewId) nav.classList.add('active');
            else nav.classList.remove('active');
        });

        // Update Content
        views.forEach(view => {
            if (view.id === viewId) {
                view.style.display = 'flex';
                setTimeout(() => view.classList.add('active'), 50);
            } else {
                view.classList.remove('active');
                setTimeout(() => view.style.display = 'none', 300);
            }
        });

        // Specific view initialization
        if (viewId === 'dashboard-view') {
            console.log('Switched to Dashboard');
        } else if (viewId === 'settings-view') {
            console.log('Switched to Settings');
        }
    };

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const viewId = item.getAttribute('data-view');
            if (viewId) switchView(viewId);
        });
    });

    if (csvFile && fileLabel) {
        csvFile.addEventListener('change', (e) => {
            const name = e.target.files[0]?.name;
            if (name) fileLabel.textContent = name.length > 22 ? name.substring(0, 19) + '...' : name;
        });
    }

    // Helper: inject plot image or fallback text
    const setPlot = (container, b64, alt) => {
        if (!container) return;
        if (b64) {
            container.innerHTML = '<img src="data:image/png;base64,' + b64 + '" class="diagnostic-img" alt="' + alt + '" style="width:100%;height:auto;border-radius:8px;">';
        } else {
            container.innerHTML = '<p class="hint">No ' + alt + ' data for this sample.</p>';
        }
    };

    // Prediction Summary panel
    const renderPredictionSummary = (label, confidence, topFeatures) => {
        if (!predSummary) return;
        const isThreat   = label && label !== 'BENIGN';
        const labelColor = isThreat ? '#f87171' : '#34d399';
        const labelIcon  = '';

        let featRows = '';
        if (topFeatures && topFeatures.length > 0) {
            topFeatures.slice(0, 10).forEach((f, i) => {
                const contrib  = (f.SHAP !== undefined && f.SHAP !== null) ? f.SHAP.toFixed(6) : '0.000000';
                const barWidth = (topFeatures[0].SHAP && f.SHAP) ? Math.min(100, (Math.abs(f.SHAP) / Math.abs(topFeatures[0].SHAP)) * 100).toFixed(1) : '0';
                featRows += '<tr>'
                    + '<td style="color:var(--text-secondary);width:30px">' + (i+1) + '</td>'
                    + '<td style="font-family:JetBrains Mono,monospace;color:#a78bfa">' + (f.Feature || f.Rank) + '</td>'
                    + '<td style="width:120px"><div style="background:rgba(167,139,250,0.15);border-radius:4px;overflow:hidden;height:8px"><div style="width:' + barWidth + '%;background:linear-gradient(90deg,#818cf8,#38bdf8);height:100%;border-radius:4px"></div></div></td>'
                    + '<td style="font-family:JetBrains Mono,monospace;color:#38bdf8;text-align:right">' + contrib + '</td>'
                    + '</tr>';
            });
        } else {
            featRows = '<tr><td colspan="4" style="color:var(--text-muted)">Feature data not available</td></tr>';
        }

        predSummary.innerHTML = '<div style="padding:1rem">'
            + '<div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:1.25rem;padding-bottom:1rem;border-bottom:1px solid rgba(255,255,255,0.07)">'
            + '<span style="font-size:1.5rem">' + labelIcon + '</span>'
            + '<div><div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em">Prediction</div>'
            + '<div style="font-size:1.25rem;font-weight:800;color:' + labelColor + '">' + (label || 'UNKNOWN') + '</div></div>'
            + '<div style="margin-left:auto;text-align:right"><div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em">Confidence</div>'
            + '<div style="font-size:1.25rem;font-weight:800;color:#f59e0b">' + (confidence * 100).toFixed(2) + '%</div></div></div>'
            + '<div style="font-size:0.7rem;color:var(--accent-primary);text-transform:uppercase;letter-spacing:.08em;margin-bottom:0.6rem">Top Driving Network Features</div>'
            + '<table style="width:100%;border-collapse:collapse;font-size:0.78rem">'
            + '<thead><tr style="color:var(--text-muted);font-size:0.65rem;text-transform:uppercase">'
            + '<th style="text-align:left;padding:4px 6px">#</th><th style="text-align:left;padding:4px 6px">Feature</th>'
            + '<th style="padding:4px 6px">Impact</th><th style="text-align:right;padding:4px 6px">Contribution</th>'
            + '</tr></thead><tbody>' + featRows + '</tbody></table></div>';
    };

    // Threat Intelligence Module (NEW)
    const renderThreatIntelligence = (intel) => {
        if (!threatIntelContainer || !intel) return;

        if (threatBadgeContainer) {
            threatBadgeContainer.innerHTML = '<span class="status-badge" style="background:' + intel.color + '22; color:' + intel.color + '; border:1px solid ' + intel.color + '44">' 
                + intel.icon + ' ' + intel.level + '</span>';
        }

        let patternsHtml = '';
        if (intel.patterns && intel.patterns.length > 0) {
            patternsHtml = '<div style="margin-top:1rem"><div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.5rem">Observed Attack Patterns</div>'
                + '<ul style="padding-left:1.2rem;font-size:0.8rem;color:var(--text-secondary);margin:0">'
                + intel.patterns.map(p => '<li style="margin-bottom:0.3rem">' + p + '</li>').join('')
                + '</ul></div>';
        }

        const renderRecommendation = (rec) => {
            if (!rec) return "N/A";
            return (typeof rec === 'object') ? (rec.recommendation || JSON.stringify(rec)) : rec;
        };

        threatIntelContainer.innerHTML = '<div style="padding:1rem">'
            + '<div>'
            + '  <div style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:0.5rem">Recommended Action</div>'
            + '  <div style="background:rgba(255,255,255,0.03);padding:1.25rem;border-radius:8px;border-left:4px solid ' + intel.color + ';line-height:1.6;color:var(--text-primary);white-space:pre-line">'
            + renderRecommendation(intel.recommendation)
            + '  </div>'
            + patternsHtml
            + '</div>'
            + '</div>';
    };

    // XAI Comparison Module (Updated for Global Performance)

    // Feature Contribution text panel (2-column, full-width)
    const renderFeatureContribution = (topFeatures, label) => {
        if (!featContrib) return;
        if (!topFeatures || topFeatures.length === 0) {
            featContrib.innerHTML = '<p class="hint">Feature data unavailable.</p>';
            return;
        }
        const maxVal = topFeatures[0].SHAP || 1;
        const items  = topFeatures.slice(0, 10);
        const half   = Math.ceil(items.length / 2);

        const makeRow = (f, i) => {
            const shapVal = (f.SHAP !== undefined && f.SHAP !== null) ? f.SHAP : 0;
            const pct = (maxVal && shapVal) ? Math.min(100, (Math.abs(shapVal) / Math.abs(maxVal)) * 100).toFixed(1) : '0';
            return '<div style="display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.04)">'
                + '<span style="width:18px;color:var(--text-muted);font-size:0.68rem;flex-shrink:0;text-align:right">' + (i+1) + '</span>'
                + '<span style="font-family:JetBrains Mono,monospace;color:#a78bfa;width:52px;flex-shrink:0;font-size:0.78rem">' + f.Feature + '</span>'
                + '<div style="flex:1;background:rgba(129,140,248,0.12);border-radius:4px;height:6px;overflow:hidden">'
                + '<div style="width:' + pct + '%;height:100%;background:linear-gradient(90deg,#818cf8,#22d3ee);border-radius:4px"></div></div>'
                + '<span style="font-family:JetBrains Mono,monospace;color:#38bdf8;font-size:0.72rem;width:80px;text-align:right;flex-shrink:0">' + shapVal.toFixed(6) + '</span>'
                + '</div>';
        };

        const col1 = items.slice(0, half).map((f, i) => makeRow(f, i)).join('');
        const col2 = items.slice(half).map((f, i) => makeRow(f, i + half)).join('');

        featContrib.innerHTML = '<div style="padding:1rem">'
            + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:2rem">'
            + '<div>' + col1 + '</div><div>' + col2 + '</div>'
            + '</div></div>';
    };

    const renderBehavioralComparison = (data) => {
        if (!data || !data.metrics) return;
        const ctx = document.getElementById('behavioralChart');
        if (!ctx) return;

        if (!data.metrics || data.metrics.length === 0) {
            if (behavioralContainer) behavioralContainer.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--text-muted);font-size:0.8rem">Physical network metadata (Bytes/s, IAT) not found in dataset headers.</div>';
            return;
        }

        if (behavioralChartObj) {
            behavioralChartObj.destroy();
        }

        const labels = data.metrics.map(m => m.name);
        const normalData = data.metrics.map(m => m.normal);
        const attackData = data.metrics.map(m => m.attack);

        behavioralChartObj = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Average Normal',
                        data: normalData,
                        backgroundColor: 'rgba(52, 211, 153, 0.6)',
                        borderColor: '#34d399',
                        borderWidth: 1
                    },
                    {
                        label: 'Average Attack',
                        data: attackData,
                        backgroundColor: 'rgba(248, 113, 113, 0.6)',
                        borderColor: '#f87171',
                        borderWidth: 1
                    }
                ]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                        labels: { color: '#94a3b8', font: { size: 10 } }
                    }
                },
                scales: {
                    x: {
                        type: 'logarithmic',
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { 
                            color: '#94a3b8', 
                            font: { size: 10 },
                            callback: function(value, index, values) {
                                if (value === 0) return '0';
                                return value.toLocaleString();
                            }
                        }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: '#f8fafc', font: { size: 11 } }
                    }
                }
            }
        });
    };

    // Render Full Scan Summary
    const renderScanSummary = (summary) => {
        if (!scanSummary || !summary) return;
        
        let breakdownRows = '';
        if (summary.breakdown) {
            for (const [category, count] of Object.entries(summary.breakdown)) {
                breakdownRows += '<tr>'
                    + '<td style="font-family:JetBrains Mono;color:var(--text-secondary)">' + category + '</td>'
                    + '<td style="text-align:right;font-family:JetBrains Mono;color:var(--accent-primary)">' + count + '</td>'
                    + '</tr>';
            }
        }

        scanSummary.innerHTML = '<div style="padding:1rem;display:grid;grid-template-columns:1fr 1fr;gap:2rem">'
            + '<div>'
            + '  <div style="font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:1rem">High-Level Metrics</div>'
            + '  <div style="display:flex;flex-direction:column;gap:1rem">'
            + '    <div style="background:rgba(255,255,255,0.03);padding:1rem;border-radius:8px;border-left:4px solid var(--accent-primary)">'
            + '      <div style="font-size:0.7rem;color:var(--text-muted)">Total Records Scanned</div>'
            + '      <div style="font-size:1.5rem;font-weight:800">' + (summary.total_rows || 0) + '</div>'
            + '    </div>'
            + '    <div style="background:rgba(255,255,255,0.03);padding:1rem;border-radius:8px;border-left:4px solid ' + (summary.threat_found ? '#f87171' : '#34d399') + '">'
            + '      <div style="font-size:0.7rem;color:var(--text-muted)">Threats Detected</div>'
            + '      <div style="font-size:1.5rem;font-weight:800;color:' + (summary.threat_found ? '#f87171' : '#34d399') + '">' + (summary.threat_count || 0) + '</div>'
            + '    </div>'
            + '  </div>'
            + '</div>'
            + '<div>'
            + '  <div style="font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:1rem">Detection Breakdown by Type</div>'
            + '  <table style="width:100%;border-collapse:collapse;font-size:0.85rem">'
            + '    <thead style="color:var(--text-muted);font-size:0.65rem;text-transform:uppercase">'
            + '      <tr style="border-bottom:1px solid rgba(255,255,255,0.07)"><th style="text-align:left;padding:8px">Category</th><th style="text-align:right;padding:8px">Count</th></tr>'
            + '    </thead>'
            + '    <tbody>' + breakdownRows + '</tbody>'
            + '  </table>'
            + '</div>'
            + '</div>';
    };

    // Main Analysis Handler
    if (analyzeBtn) {
        analyzeBtn.addEventListener('click', async () => {
            if (isAnalyzing) return;
            if (!csvFile || !csvFile.files[0]) { alert('Please select a CSV file first.'); return; }

            isAnalyzing = true;
            analyzeBtn.disabled = true;
            analyzeBtn.innerHTML = '<span class="spinner"></span> Analyzing...';

            const loader = (text) => '<div class="loading-wrapper"><div class="spinner spinner-lg"></div><p>' + text + '</p></div>';

            if (analysisResult) analysisResult.innerHTML = '<div class="result-box processing">Initializing Neural Engine...</div>';
            if (shapWaterfall)  shapWaterfall.innerHTML  = loader('Computing SHAP waterfall...');
            if (shapBar)        shapBar.innerHTML        = loader('Computing class-wise impact...');
            if (shapSummary)    shapSummary.innerHTML    = loader('Computing SHAP summary...');
            if (shapBeeswarm)   shapBeeswarm.innerHTML   = loader('Computing beeswarm plot...');
            if (dataRule)       dataRule.innerHTML       = '<p class="hint" style="animation:pulse 2s infinite">Extracting decision rules...</p>';
            if (cfContainer)    cfContainer.innerHTML    = '<p class="hint" style="animation:pulse 2s infinite">Simulating counterfactuals...</p>';
            if (llmContainer)   llmContainer.innerHTML   = '<p class="hint" style="animation:pulse 2s infinite">Amazon Bedrock AI is generating security reflections...</p>';
            if (predSummary)    predSummary.innerHTML    = '<div class="loading-wrapper"><div class="spinner"></div><p>Computing prediction...</p></div>';
            if (featContrib)    featContrib.innerHTML    = '<div class="loading-wrapper"><div class="spinner"></div><p>Ranking features...</p></div>';
            if (threatIntelContainer) threatIntelContainer.innerHTML = loader('Analyzing threat patterns...');
            if (alignmentContainer)   alignmentContainer.innerHTML   = loader('Verifying model alignment...');
            if (threatBadgeContainer) threatBadgeContainer.innerHTML = '';
            if (downloadPdfBtn) downloadPdfBtn.style.display = 'none';

            const formData = new FormData();
            formData.append('file', csvFile.files[0]);

            try {
                const res  = await fetch('/api/analyze_csv', { method: 'POST', body: formData });
                const data = await res.json();
                console.log('Response:', data);

                if (data.error) {
                    if (analysisResult) analysisResult.innerHTML = '<div class="result-box danger">ERROR: ' + data.error + '</div>';
                    return;
                }

                lastData = data;

                // Result Banner
                if (data.dataset_meta && data.dataset_meta.scan_summary) {
                    const s   = data.dataset_meta.scan_summary;
                    const cls = s.threat_found ? 'danger' : 'success';
                    const txt = s.threat_found ? 'THREATS DETECTED' : 'SYSTEM CLEAR';
                    if (analysisResult) analysisResult.innerHTML = '<div class="result-box ' + cls + ' animate-fade">'
                        + '<span class="status-msg">' + txt + '</span>'
                        + '<span class="detail-msg">Target: <strong>' + data.label + '</strong> &mdash; Confidence: ' + (data.confidence * 100).toFixed(2) + '%</span>'
                        + '</div>';
                }

                // Prediction Summary & Feature Contribution
                renderPredictionSummary(data.label, data.confidence, data.top_features);
                renderFeatureContribution(data.top_features, data.label);
                
                // Full Scan Summary
                if (data.dataset_meta && data.dataset_meta.scan_summary) {
                    renderScanSummary(data.dataset_meta.scan_summary);
                }

                // Threat Intelligence & Alignment
                if (data.threat_intel) {
                    renderThreatIntelligence(data.threat_intel);
                }

                if (data.behavioral_comparison) {
                    renderBehavioralComparison(data.behavioral_comparison);
                }

                // Plots  (beeswarm used for both beeswarm slot AND summary slot)
                setPlot(shapBeeswarm,  data.shap_plots && data.shap_plots.beeswarm,  'SHAP Beeswarm');
                setPlot(shapSummary,   data.shap_plots && data.shap_plots.beeswarm,  'SHAP Summary');
                setPlot(shapWaterfall, data.shap_plots && data.shap_plots.waterfall, 'SHAP Waterfall');
                setPlot(shapBar,       data.shap_plots && data.shap_plots.class_bar, 'Class-Wise Impact');

                // Text panels
                if (dataRule)    dataRule.textContent    = data.decision_path  || 'No decision path for this model type.';
                if (llmContainer) {
                    llmContainer.innerHTML = '<div class="loading-pulse">AI is analyzing behavioral features...</div>';
                    
                    setTimeout(() => {
                        let reflection = data.llm_reflection;
                        if (typeof reflection === 'object' && reflection !== null) {
                            reflection = reflection.assessment || JSON.stringify(reflection);
                        }
                        llmContainer.textContent = reflection || "No AI analysis available.";
                        llmContainer.style.color = "#d1d5db";
                    }, 100);
                }
                if (cfContainer) cfContainer.textContent = data.counterfactual || 'No counterfactual found for this prediction.';

                if (downloadPdfBtn) downloadPdfBtn.style.display = 'inline-flex';

            } catch (e) {
                console.error('Analysis error:', e);
                if (analysisResult) analysisResult.innerHTML = '<div class="result-box danger">Communication error - check server.</div>';
            } finally {
                isAnalyzing = false;
                analyzeBtn.disabled = false;
                analyzeBtn.textContent = 'Run Diagnostics';
            }
        });
    }

    // PDF Download
    if (downloadPdfBtn) {
        downloadPdfBtn.addEventListener('click', async () => {
            if (!lastData) return;
            downloadPdfBtn.textContent = 'Generating...';
            downloadPdfBtn.disabled = true;
            try {
                const res = await fetch('/api/download_pdf', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(lastData)
                });
                if (res.ok) {
                    const blob = await res.blob();
                    const url  = URL.createObjectURL(blob);
                    const a    = document.createElement('a');
                    a.href = url; a.download = 'AI-Threat_Report_' + Date.now() + '.pdf';
                    document.body.appendChild(a); a.click();
                    URL.revokeObjectURL(url); document.body.removeChild(a);
                }
            } catch (e) { console.error('PDF error:', e); }
            finally { downloadPdfBtn.textContent = 'Export PDF'; downloadPdfBtn.disabled = false; }
        });
    }

    // Pre-populate baseline metrics table on load
    // renderMetricsTable([], modelSelect ? modelSelect.value : 'Best Model');

});
