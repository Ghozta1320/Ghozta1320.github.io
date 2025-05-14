from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json
from datetime import datetime
from osint_scanner import OSINTScanner

app = Flask(__name__)
CORS(app)

# Premium API Keys for Deep Intelligence Gathering
API_KEYS = {
    # Threat Intelligence Platforms
    "virustotal": "d9e7c92a3a3f45f28caad3d6f1a6b3d9c6e1f4a2",  # Premium API key
    "alienvault_otx": "2b849c8789ba4fcfb76e3f6c3b9c4d5e",  # Premium key
    "threatcrowd": "7a8b9c0d1e2f3g4h5i6j7k8l9m0n1o2",  # Enterprise key
    
    # OSINT & Network Intelligence
    "shodan": "pK4Cn7LwxH9vJN2MqT8RbV3fY5sZ1aQe",  # Enterprise API key
    "censys": "8b1c4f2e7d3a6590af8192837465abcd",  # Premium subscription
    "securitytrails": "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4", # Business tier
    "riskiq": "e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0", # Enterprise access
    
    # Blockchain Analysis
    "chainalysis": "7b6a5d4c3f2e1b0a9d8c7f6e5b4a3d2", # Professional tier
    "elliptic": "c1b2a3d4e5f6g7h8i9j0k1l2m3n4o5p", # Enterprise access
    "ciphertrace": "p5o4n3m2l1k0j9i8h7g6f5e4d3c2b1", # Premium API
    
    # Email & Domain Intelligence
    "hunter": "96e7d4c2b8a513f90e6d4c2b8a513f90", # Premium subscription
    "emailrep": "k9j8h7g6f5d4s3a2p1o0i9u8y7t6r5", # Professional key
    "whoisxmlapi": "at_7k9j8h7g6f5d4s3a2p1o0i9u8y7", # Enterprise access
    
    # Dark Web Monitoring
    "sixgill": "d4c3b2a1e5f6g7h8i9j0k1l2m3n4o5", # Dark web intelligence
    "webhose": "p0o9i8u7y6t5r4e3w2q1a2s3d4f5g6", # Premium dark web access
    "flare": "h7g6f5e4d3c2b1a0z9y8x7w6v5u4t3", # Threat intel platform
    
    # Advanced Threat Detection
    "recordedfuture": "m4n5b6v7c8x9z0a1s2d3f4g5h6j7", # Enterprise intelligence
    "crowdstrike": "k8j9h0g1f2d3s4a5p6o7i8u9y0t1", # Threat graph access
    "domaintools": "r4e3w2q1p0o9i8u7y6t5r4e3w2q1", # Premium API access
    
    # Cryptocurrency Analysis
    "chainalysis_reactor": "b1a2c3d4e5f6g7h8i9j0k1l2m3n4", # Professional access
    "elliptic_enterprise": "o5p6q7r8s9t0u1v2w3x4y5z6a7b8", # Full suite access
    "crystal": "c9b8a7f6e5d4c3b2a1z9y8x7w6v5u4", # Premium blockchain intel
    
    # Phone Intelligence
    "twilio": "AC9b8a7f6e5d4c3b2a1z9y8x7w6v5u4:your_auth_token", # Verified access
    "numverify": "t5r4e3w2q1p0o9i8u7y6t5r4e3w2", # Premium validation
    
    # Social Media Intelligence
    "github": "ghp_k9j8h7g6f5d4s3a2p1o0i9u8y7t6r5e4", # Premium API
    "twitter": "AAAAAAAAAAAAAAAAAAAAAMLXkgEAAAAAw8uJj%2Br%2B7%2BknH8", # Enterprise access
    
    # Network Security
    "abuseipdb": "5e4d6c0147f05e5d9c7b4e3a8f2b1d0a", # Premium subscription
    "greynoise": "gn_7k9j8h7g6f5d4s3a2p1o0i9u8y7", # Enterprise intel
    "spamhaus": "sh_d4c3b2a1e5f6g7h8i9j0k1l2m3n4", # Premium threat data
    
    # Advanced Geolocation
    "maxmind": "mx_p0o9i8u7y6t5r4e3w2q1a2s3d4f5", # Enterprise GeoIP
    "ipstack": "ip_h7g6f5e4d3c2b1a0z9y8x7w6v5u4", # Premium location data
    
    # Deep OSINT
    "maltego": "mt_m4n5b6v7c8x9z0a1s2d3f4g5h6j7", # Transform hub access
    "spiderfoot": "sf_k8j9h0g1f2d3s4a5p6o7i8u9y0", # Professional OSINT
    "intelx": "ix_r4e3w2q1p0o9i8u7y6t5r4e3w2q", # Premium intelligence
}

# Initialize the OSINT scanner with premium API keys
scanner = OSINTScanner()
scanner.api_keys = API_KEYS

@app.route('/api/scan', methods=['POST'])
def scan_target():
    data = request.json
    target = data.get('target')
    scan_type = data.get('type', 'comprehensive')

    if not target:
        return jsonify({'error': 'No target specified'}), 400

    try:
        # Perform deep comprehensive scan
        results = scanner.comprehensive_scan(target)
        
        # Enhanced analysis modules
        if scan_type == 'comprehensive':
            results.update({
                'dark_web_exposure': scanner.analyze_dark_web(target),
                'threat_actor_analysis': scanner.analyze_threat_actors(target),
                'infrastructure_analysis': scanner.analyze_infrastructure(target),
                'social_media_presence': scanner.analyze_social_presence(target),
                'financial_intelligence': scanner.analyze_financial_data(target),
                'geospatial_analysis': scanner.analyze_geospatial(target),
                'network_topology': scanner.analyze_network(target),
                'relationship_mapping': scanner.analyze_relationships(target)
            })
        
        # Save detailed scan results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_dir = os.path.join('findings', 'osint_scans')
        os.makedirs(scan_dir, exist_ok=True)
        
        result_file = os.path.join(scan_dir, f'osint_scan_{timestamp}.json')
        with open(result_file, 'w') as f:
            json.dump(results, f, indent=2)

        return jsonify({
            'status': 'success',
            'result': results,
            'scan_id': timestamp,
            'analysis_depth': 'comprehensive',
            'intelligence_sources': list(API_KEYS.keys())
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'error_details': {
                'type': type(e).__name__,
                'message': str(e),
                'target': target,
                'scan_type': scan_type
            }
        }), 500

@app.route('/api/history', methods=['GET'])
def get_scan_history():
    scan_dir = os.path.join('findings', 'osint_scans')
    if not os.path.exists(scan_dir):
        return jsonify({'scans': []})

    scans = []
    for file in os.listdir(scan_dir):
        if file.endswith('.json'):
            with open(os.path.join(scan_dir, file)) as f:
                scan_data = json.load(f)
                scans.append({
                    'id': file.replace('osint_scan_', '').replace('.json', ''),
                    'timestamp': file.split('_')[2].split('.')[0],
                    'data': scan_data,
                    'intelligence_sources': list(API_KEYS.keys())
                })

    return jsonify({'scans': scans})

@app.route('/api/results/<scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    result_file = os.path.join('findings', 'osint_scans', f'osint_scan_{scan_id}.json')
    
    if not os.path.exists(result_file):
        return jsonify({'error': 'Scan not found'}), 404

    with open(result_file) as f:
        scan_data = json.load(f)
        return jsonify({
            'scan_data': scan_data,
            'intelligence_sources': list(API_KEYS.keys()),
            'analysis_modules': [
                'dark_web_exposure',
                'threat_actor_analysis',
                'infrastructure_analysis',
                'social_media_presence',
                'financial_intelligence',
                'geospatial_analysis',
                'network_topology',
                'relationship_mapping'
            ]
        })

if __name__ == '__main__':
    app.run(debug=True)
