"""
Web Interface Integration Tests
Tests integration between scanners and web frontend
"""

import unittest
import json
from datetime import datetime
from scanner_modules import (
    PhoneScanner, EmailScanner, DomainScanner,
    ThreatScanner, SocialScanner
)
from breach_scanner import BreachScanner
from deep_scanner import DeepScanner
from flask import Flask, jsonify, request

class TestWebIntegration(unittest.TestCase):
    """Test cases for web interface integration"""

    def setUp(self):
        """Set up test fixtures"""
        self.app = Flask(__name__)
        self.client = self.app.test_client()
        
        self.test_data = {
            "email": "test@example.com",
            "phone": "+1234567890",
            "domain": "example.com",
            "username": "testuser"
        }
        
        self.scanners = {
            "phone": PhoneScanner(),
            "email": EmailScanner(),
            "domain": DomainScanner(),
            "breach": BreachScanner(),
            "threat": ThreatScanner(),
            "social": SocialScanner()
        }
        
        # Set up API endpoints
        @self.app.route('/api/scan/<scan_type>', methods=['POST'])
        def scan_endpoint(scan_type):
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
                    
                if scan_type not in self.scanners:
                    return jsonify({
                        "error": "Invalid scanner type",
                        "valid_types": list(self.scanners.keys()),
                        "timestamp": datetime.now().isoformat()
                    }), 400
                    
                # Get provider
                provider = data.get('provider')
                
                scanner = self.scanners[scan_type]
                result = scanner.gather_intelligence(target, provider)
                
                return jsonify({
                    "timestamp": datetime.now().isoformat(),
                    "scanner": scan_type,
                    "target": target,
                    "result": result
                })
                
            except Exception as e:
                return jsonify({
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                }), 500
            
        @self.app.route('/api/deep-scan', methods=['POST'])
        def deep_scan_endpoint():
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

    def test_individual_scanner_endpoints(self):
        """Test individual scanner API endpoints"""
        print("\nTesting Scanner API Endpoints...")
        
        for scanner_type, scanner in self.scanners.items():
            with self.subTest(scanner=scanner_type):
                target = self.test_data.get(
                    "email" if scanner_type in ["email", "breach"] else
                    "domain" if scanner_type in ["domain", "threat"] else
                    "username" if scanner_type == "social" else
                    "phone"
                )
                
                response = self.client.post(
                    f'/api/scan/{scanner_type}',
                    json={"target": target}
                )
                
                self.assertEqual(response.status_code, 200)
                result = json.loads(response.data)
                self.assertIsInstance(result, dict)
                print(f"\n{scanner_type.title()} Scanner API Response:")
                print(json.dumps(result, indent=2))

    def test_deep_scan_endpoint(self):
        """Test deep scan API endpoint"""
        print("\nTesting Deep Scan API Endpoint...")
        
        response = self.client.post(
            '/api/deep-scan',
            json={
                "target": self.test_data["email"],
                "scan_types": ["EMAIL_INTELLIGENCE", "BREACH_INTELLIGENCE"]
            }
        )
        
        self.assertEqual(response.status_code, 200)
        result = json.loads(response.data)
        self.assertIsInstance(result, dict)
        self.assertIn("scan_metadata", result)
        self.assertIn("intelligence_data", result)
        print("\nDeep Scan API Response:")
        print(json.dumps(result, indent=2))

    def test_error_handling(self):
        """Test API error handling"""
        print("\nTesting API Error Handling...")
        
        # Test invalid scanner type
        response = self.client.post(
            '/api/scan/invalid_scanner',
            json={"target": "test"}
        )
        self.assertEqual(response.status_code, 400)
        
        # Test missing target
        response = self.client.post(
            '/api/scan/email',
            json={}
        )
        self.assertEqual(response.status_code, 400)
        
        # Test invalid JSON
        response = self.client.post(
            '/api/scan/email',
            data="invalid json"
        )
        self.assertEqual(response.status_code, 400)

    def test_concurrent_requests(self):
        """Test handling of concurrent API requests"""
        print("\nTesting Concurrent API Requests...")
        
        import threading
        import time
        
        def make_request():
            response = self.client.post(
                '/api/scan/email',
                json={"target": self.test_data["email"]}
            )
            self.assertEqual(response.status_code, 200)
        
        threads = []
        start_time = time.time()
        
        # Launch 5 concurrent requests
        for _ in range(5):
            thread = threading.Thread(target=make_request)
            thread.start()
            threads.append(thread)
        
        # Wait for all requests to complete
        for thread in threads:
            thread.join()
            
        duration = time.time() - start_time
        print(f"\nProcessed 5 concurrent requests in {duration:.2f} seconds")

def run_tests():
    """Run all test cases"""
    unittest.main(verbosity=2)

if __name__ == "__main__":
    run_tests()
