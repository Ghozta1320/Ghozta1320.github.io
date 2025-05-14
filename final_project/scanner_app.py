"""
Web-based Intelligence Scanner Application
Provides a REST API for intelligence gathering operations
"""

from flask import Flask, jsonify, request, send_from_directory, send_file
import os
from scanner_modules import (
    PhoneScanner, EmailScanner, DomainScanner,
    ThreatScanner, SocialScanner
)
from breach_scanner import BreachScanner
from deep_scanner import DeepScanner
from datetime import datetime
import json

app = Flask(__name__)

# Serve static files from final_project directory
@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

# Serve index.html at root
@app.route('/')
def serve_index():
    return send_file('index.html')

# Initialize scanners
scanners = {
    "phone": PhoneScanner(),
    "email": EmailScanner(),
    "domain": DomainScanner(),
    "breach": BreachScanner(),
    "threat": ThreatScanner(),
    "social": SocialScanner()
}

@app.route('/api/scan/<scan_type>', methods=['POST'])
def scan_endpoint(scan_type):
    """Individual scanner endpoint"""
    try:
        # Validate request format
        if not request.is_json:
            return jsonify({
                "error": "Request must be JSON",
                "timestamp": datetime.now().isoformat()
            }), 400
            
        try:
            data = request.get_json()
        except Exception as e:
            return jsonify({
                "error": "Invalid JSON format",
                "details": str(e),
                "timestamp": datetime.now().isoformat()
            }), 400
            
        # Validate required fields
        target = data.get('target')
        if not target:
            return jsonify({
                "error": "Target is required",
                "timestamp": datetime.now().isoformat()
            }), 400
            
        if scan_type not in scanners:
            return jsonify({
                "error": "Invalid scanner type",
                "valid_types": list(scanners.keys()),
                "timestamp": datetime.now().isoformat()
            }), 400
            
        # Validate provider
        provider = data.get('provider')
        available_providers = scanners[scan_type].api_manager.get_providers(
            scan_type.upper() + "_INTELLIGENCE"
        )
        
        if provider and provider not in available_providers:
            return jsonify({
                "error": "Invalid provider",
                "valid_providers": list(available_providers.keys()),
                "timestamp": datetime.now().isoformat()
            }), 400
            
        if not provider:
            # Fallback to first available provider
            providers = list(available_providers.keys())
            provider = providers[0] if providers else None
            
        if not provider:
            return jsonify({
                "error": "No providers available for this scanner type",
                "timestamp": datetime.now().isoformat()
            }), 400
            
        scanner = scanners[scan_type]
        result = scanner.gather_intelligence(target, provider)
        
        # Return scanner results directly without wrapping
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

@app.route('/api/deep-scan', methods=['POST'])
def deep_scan_endpoint():
    """Deep scan endpoint"""
    try:
        # Validate request format
        if not request.is_json:
            return jsonify({
                "error": "Request must be JSON",
                "timestamp": datetime.now().isoformat()
            }), 400
            
        try:
            data = request.get_json()
        except Exception as e:
            return jsonify({
                "error": "Invalid JSON format",
                "details": str(e),
                "timestamp": datetime.now().isoformat()
            }), 400
            
        # Validate required fields
        target = data.get('target')
        if not target:
            return jsonify({
                "error": "Target is required",
                "timestamp": datetime.now().isoformat()
            }), 400
            
        scan_types = data.get('scan_types')
        if scan_types and not isinstance(scan_types, list):
            return jsonify({
                "error": "scan_types must be a list",
                "timestamp": datetime.now().isoformat()
            }), 400
            
        scanner = DeepScanner()
        scan_result = scanner.deep_scan(target, scan_types)
        
        # Extract scan_metadata and other fields from the result
        response = {
            "timestamp": datetime.now().isoformat(),
            "scan_types": scan_types or "all",
            "target": target,
            "scan_metadata": scan_result.get("scan_metadata", {}),
            "intelligence_data": scan_result.get("intelligence_data", {}),
            "correlation_analysis": scan_result.get("correlation_analysis", {}),
            "risk_assessment": scan_result.get("risk_assessment", {}),
            "recommendations": scan_result.get("recommendations", [])
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

@app.route('/api/scanners', methods=['GET'])
def list_scanners():
    """List available scanners and their capabilities"""
    scanner_info = {}
    
    for name, scanner in scanners.items():
        scanner_info[name] = {
            "description": scanner.__doc__,
            "providers": scanner.api_manager.get_providers(name.upper() + "_INTELLIGENCE")
        }
        
    return jsonify({
        "timestamp": datetime.now().isoformat(),
        "scanners": scanner_info
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    """API health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
