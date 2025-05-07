from flask import Flask, request, jsonify
from flask_cors import CORS
from osint_scanner import OSINTScanner
import asyncio
from datetime import datetime
import json
import os
from typing import Dict, Any

app = Flask(__name__)
CORS(app)

# Initialize scanner
scanner = OSINTScanner()

def save_scan_result(scan_type: str, target: str, result: Dict[str, Any]):
    """Save scan results to a JSON file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"findings/{scan_type}_scans/scan_{timestamp}.json"
    
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    data = {
        "timestamp": timestamp,
        "target": target,
        "type": scan_type,
        "result": result
    }
    
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

@app.route('/api/scan', methods=['POST'])
async def scan():
    data = request.json
    target = data.get('target')
    scan_type = data.get('type', 'all')

    if not target:
        return jsonify({"error": "No target provided"}), 400

    try:
        results = {}
        
        # Determine target type and run appropriate scans
        if '@' in target:  # Email analysis
            results['email'] = await scanner.analyze_email(target)
            
        elif target.startswith(('0x', '1', '3', 'bc')):  # Crypto address
            results['crypto'] = await scanner.analyze_crypto(target)
            
        elif any(c.isdigit() for c in target):  # Phone number
            results['phone'] = await scanner.analyze_phone(target)
            
        else:  # Domain/URL analysis
            results['domain'] = await scanner.analyze_domain(target)

        # Save results
        save_scan_result(scan_type, target, results)

        return jsonify({
            "status": "success",
            "result": results
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500

@app.route('/api/submit-tip', methods=['POST'])
def submit_tip():
    """Handle tip submissions"""
    data = request.json
    
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"findings/tips/tip_{timestamp}.json"
        
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        # TODO: Add notification system for urgent tips
        if data.get('urgency') == 'high':
            # Implement notification system
            pass
        
        return jsonify({
            "status": "success",
            "message": "Tip submitted successfully"
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500

@app.route('/api/phone-intel', methods=['POST'])
async def phone_intel():
    """Enhanced phone number intelligence endpoint"""
    data = request.json
    phone = data.get('target')
    
    if not phone:
        return jsonify({"error": "No phone number provided"}), 400
        
    try:
        results = await scanner.analyze_phone(phone)
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/email-analysis', methods=['POST'])
async def email_analysis():
    """Enhanced email analysis endpoint"""
    data = request.json
    email = data.get('target')
    
    if not email:
        return jsonify({"error": "No email provided"}), 400
        
    try:
        results = await scanner.analyze_email(email)
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/domain-recon', methods=['POST'])
async def domain_recon():
    """Enhanced domain reconnaissance endpoint"""
    data = request.json
    domain = data.get('target')
    
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
        
    try:
        results = await scanner.analyze_domain(domain)
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/crypto-investigation', methods=['POST'])
async def crypto_investigation():
    """Enhanced cryptocurrency investigation endpoint"""
    data = request.json
    address = data.get('target')
    
    if not address:
        return jsonify({"error": "No crypto address provided"}), 400
        
    try:
        results = await scanner.analyze_crypto(address)
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/health')
def health_check():
    """API health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
