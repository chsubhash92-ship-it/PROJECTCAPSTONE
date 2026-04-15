import boto3
import sys
import os

# Ensure the root directory is in sys.path for reliable config importing
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import config
import json

def generate_security_analysis(scan_data):
    """
    Generates technical remediation and behavioral pattern analysis.
    """
    if config.AWS_ACCESS_KEY_ID == "YOUR_AWS_ACCESS_KEY":
        return "AWS Credentials not configured. Please add AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to config.py."

    try:
        # Initialize Bedrock Runtime client
        bedrock = boto3.client(
            service_name='bedrock-runtime',
            aws_access_key_id=config.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=config.AWS_SECRET_ACCESS_KEY,
            region_name=config.AWS_REGION_NAME
        )

        model_id = config.BEDROCK_MODEL_ID

        # Construct a structured prompt for dynamic intelligence
        prompt = f"""
        Human: You are a Senior Network Intrusion Detection System (NIDS) Security Architect with expertise in anomaly detection, ML-based threat classification, and Explainable AI (XAI).

        Analyze the network scan results provided below and generate a structured, technical security report.

        Context:
        - Target Classification: {scan_data.get('label', 'UNKNOWN')}
        - Model Confidence: {(scan_data.get('confidence') or 0)*100:.2f}%
        - Top Contributing Features (XAI): {scan_data.get('top_features', ['PC1','PC2','PC3'])}

        STRICT INSTRUCTIONS:
        - Output must contain ONLY the three sections defined below.
        - No extra explanations, no headings outside the format, no code blocks.
        - Maintain a professional cybersecurity tone (like a SOC analyst report).
        - Be precise, technical, and avoid generic statements.

        ----------------------------

        [DETAILED SECURITY ASSESSMENT]
        Provide ~250 words covering:
        - Nature of the detected activity (DoS, DDoS, Probe, etc.)
        - Traffic behavior (packet rate, flow duration, anomalies)
        - Indicators of compromise (IoCs)
        - Impact on system/network (availability, latency, resource exhaustion)
        - Correlation with known attack patterns or signatures
        - Confidence interpretation (is this reliable or borderline detection?)

        ----------------------------

        [TECHNICAL REMEDIATION TO STOP ATTACK]
        Provide EXACT mitigation steps:
        - 4–5 bullet points ONLY
        - Each MUST include a real Linux command (iptables, ufw, tcpdump, netstat, etc.)
        - Must be immediately actionable in production
        - Include at least:
        • One blocking rule
        • One rate-limiting rule
        • One monitoring/forensics command

        Example format:
        - sudo iptables -A INPUT -s <malicious_ip> -j DROP

        ----------------------------

        [BEHAVIORAL ATTACK PATTERNS]
        Analyze model explainability (XAI insights):

        - Pattern 1: Explain how "{scan_data.get('top_features', ['PC1'])[0]}" contributes to attack detection and what abnormal behavior it represents.
        - Pattern 2: Explain how "{scan_data.get('top_features', ['PC1','PC2'])[1]}" correlates with malicious traffic patterns.
        - Pattern 3: Explain how "{scan_data.get('top_features', ['PC1','PC2','PC3'])[2]}" indicates deviation from normal baseline traffic.

        Each pattern must:
        - Link feature → behavior → attack implication
        - Be concise but technically meaningful

        ----------------------------

        END OF RESPONSE.
        Assistant:
        """        
        # Prepare body based on model family
        if "claude-3" in model_id:
            body = json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 2000,
                "stop_sequences": ["END OF RESPONSE.", "Human:", "Assistant:"],
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": prompt
                            }
                        ]
                    }
                ]
            })
        elif "nova" in model_id:
            body = json.dumps({
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "text": prompt
                            }
                        ]
                    }
                ],
                "inferenceConfig": {
                    "maxTokens": 2000,
                    "stopSequences": ["END OF RESPONSE.", "Human:"],
                    "temperature": 0
                }
            })
        elif "llama" in model_id:
            body = json.dumps({
                "prompt": prompt,
                "max_gen_len": 1024,
                "stop": ["END OF RESPONSE.", "Human:"],
                "temperature": 0.5,
                "top_p": 0.9
            })
        else:
            # Fallback for Titan/other models (Simplified)
            body = json.dumps({
                "inputText": prompt,
                "textGenerationConfig": {
                    "maxTokenCount": 2048,
                    "stopSequences": ["END OF RESPONSE.", "Human:"],
                    "temperature": 0,
                    "topP": 1
                }
            })

        response = bedrock.invoke_model(
            body=body,
            modelId=model_id,
            accept="application/json",
            contentType="application/json"
        )

        response_body = json.loads(response.get('body').read())
        
        analysis_text = ""
        if "claude-3" in model_id:
            content = response_body.get('content', [])
            if isinstance(content, list) and len(content) > 0 and content[0]:
                analysis_text = content[0].get('text', "")
            else:
                analysis_text = str(response_body)
        else:
            # Handle Llama (generation), Titan (results[0].outputText), and general completions
            if "results" in response_body:
                analysis_text = response_body['results'][0].get('outputText', "")
            elif "generation" in response_body:
                analysis_text = response_body.get('generation', "")
            elif "completion" in response_body:
                analysis_text = response_body.get('completion', "")
            elif "outputs" in response_body:
                # Handle Nova or others
                analysis_text = response_body['outputs'][0].get('text', "")
            else:
                analysis_text = ""

        # Clean up literal \n strings if they appear
        analysis_text = analysis_text.replace('\\n', '\n')

        import re
        
        # Simple parsing for structured output
        parsed_data = {
            "assessment": "",
            "recommendation": "",
            "patterns": [],
            "raw_text": analysis_text
        }
        
        try:
            # Flexible parsing using regex
            assessment_match = re.search(r'(?:\[DETAILED SECURITY ASSESSMENT\]|\[ASSESSMENT\]|\*\*Detailed Security Assessment\*\*|\*\*Assessment\*\*)(.*?)(?:\[|\*\*|$)', analysis_text, re.DOTALL | re.IGNORECASE)
            if assessment_match:
                parsed_data['assessment'] = assessment_match.group(1).strip()
            
            # Match RECOMMENDATION or TECHNICAL REMEDIATION TO STOP ATTACK or MITIGATION STEPS (Handle colons/bullets)
            rec_match = re.search(r'(?:\[TECHNICAL REMEDIATION TO STOP ATTACK\]|\[RECOMMENDATION\]|\[MITIGATION STEPS\]|\*\*Technical Remediation to Stop Attack\*\*|\*\*Mitigation Steps\*\*)[:\s]*(.*?)(?:\[|\*\*|$)', analysis_text, re.DOTALL | re.IGNORECASE)
            if rec_match:
                parsed_data['recommendation'] = rec_match.group(1).strip()

            # Match BEHAVIORAL ATTACK PATTERNS or OBSERVED PATTERNS 
            patterns_match = re.search(r'(?:\[BEHAVIORAL ATTACK PATTERNS\]|\[OBSERVED PATTERNS\]|\*\*Behavioral Attack Patterns\*\*|\*\*Observed Patterns\*\*)[:\s]*(.*?)(?:\[|\*\*|$)', analysis_text, re.DOTALL | re.IGNORECASE)
            if patterns_match:
                p_text = patterns_match.group(1).strip()
                # Clean up lines and filter for bullet-like content
                parsed_data['patterns'] = [p.strip('- *•').strip() for p in p_text.split('\n') if p.strip('- *•').strip()]
                
            # Fallback if parsing returned nothing but text exists
            if not parsed_data['assessment'] and analysis_text:
                # Capture everything if no tags found
                parsed_data['assessment'] = analysis_text.strip()
                
        except Exception as e:
            print(f"Parsing error: {e}")
            parsed_data['assessment'] = analysis_text
            
        return parsed_data

    except Exception as e:
        import traceback
        return {"error": f"Error generating Bedrock analysis: {str(e)}\n{traceback.format_exc()}"}


def generate_security_reflection(scan_data):
    """
    Generates a concise 100-word security reflection for the main dashboard card.
    """
    if config.AWS_ACCESS_KEY_ID == "YOUR_AWS_ACCESS_KEY":
        return {"assessment": "AWS Credentials not configured."}

    try:
        bedrock = boto3.client(
            service_name='bedrock-runtime',
            aws_access_key_id=config.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=config.AWS_SECRET_ACCESS_KEY,
            region_name=config.AWS_REGION_NAME
        )

        model_id = config.BEDROCK_MODEL_ID
        prompt = f"""
        Human: You are a NIDS Security Architect. 
        Provide a concise security reflection on this detection:
        - Target: {scan_data.get('label', 'UNKNOWN')}
        - Confidence: {(scan_data.get('confidence') or 0)*100:.2f}%
        - Key Features: {scan_data.get('top_features', [])[:3]}

        [DETAILED SECURITY ASSESSMENT]
        Provide EXACTLY 100 words (no more, no less) explaining the nature of this threat, its immediate impact on network stability, and why it was identified as {scan_data.get('label', 'malicious')}. Maintain a professional, executive tone.

        END OF RESPONSE.
        Assistant:"""

        # Prepare body based on model family (same logic as generate_security_analysis)
        if "claude-3" in model_id:
            body = json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 500,
                "stop_sequences": ["END OF RESPONSE.", "Human:", "Assistant:"],
                "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}]
            })
        elif "nova" in model_id:
            body = json.dumps({
                "messages": [{"role": "user", "content": [{"text": prompt}]}],
                "inferenceConfig": {"maxTokens": 500, "stopSequences": ["END OF RESPONSE."], "temperature": 0}
            })
        elif "llama" in model_id:
            body = json.dumps({
                "prompt": prompt,
                "max_gen_len": 512,
                "stop": ["END OF RESPONSE."],
                "temperature": 0.5
            })
        else:
            # Fallback for Titan/other models (Simplified)
            body = json.dumps({
                "inputText": prompt,
                "textGenerationConfig": {
                    "maxTokenCount": 512,
                    "stopSequences": ["END OF RESPONSE."],
                    "temperature": 0
                }
            })

        response = bedrock.invoke_model(body=body, modelId=model_id)
        response_body = json.loads(response.get('body').read())
        
        analysis_text = ""
        if "claude-3" in model_id:
            analysis_text = response_body.get('content', [{}])[0].get('text', "")
        else:
            # Handle Llama (generation), Titan (results[0].outputText), and general completions
            if "results" in response_body:
                analysis_text = response_body['results'][0].get('outputText', "")
            elif "generation" in response_body:
                analysis_text = response_body.get('generation', "")
            elif "completion" in response_body:
                analysis_text = response_body.get('completion', "")
            elif "outputs" in response_body:
                analysis_text = response_body['outputs'][0].get('text', "")
            else:
                analysis_text = ""

        import re
        assessment_match = re.search(r'(?:\[DETAILED SECURITY ASSESSMENT\])(.*?)(?:\[|END OF RESPONSE|$)', analysis_text, re.DOTALL | re.IGNORECASE)
        reflection = assessment_match.group(1).strip() if assessment_match else analysis_text.strip()
        
        return {"assessment": reflection}

    except Exception as e:
        return {"assessment": f"Error generating reflection: {str(e)}"}
