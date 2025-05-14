"""
Test Suite for Intelligence Scanners
"""

import unittest
from datetime import datetime
from scanner_modules import (
    PhoneScanner, EmailScanner, DomainScanner,
    ThreatScanner, SocialScanner
)
from breach_scanner import BreachScanner
from deep_scanner import DeepScanner

class TestScanners(unittest.TestCase):
    """Test cases for intelligence scanners"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_data = {
            "email": "test@example.com",
            "phone": "+1234567890",
            "domain": "example.com",
            "username": "testuser"
        }
        self.deep_scanner = DeepScanner()
        self.scanners = {
            "phone": PhoneScanner(),
            "email": EmailScanner(),
            "domain": DomainScanner(),
            "breach": BreachScanner(),
            "threat": ThreatScanner(),
            "social": SocialScanner()
        }

    def test_phone_scanner(self):
        """Test phone intelligence gathering"""
        print("\nTesting Phone Scanner...")
        scanner = self.scanners["phone"]
        result = scanner.gather_intelligence(self.test_data["phone"], "phonevalidator")
        
        self.assertIsInstance(result, dict)
        self.assertIn("carrier_info", result)
        self.assertIn("location_data", result)
        print(f"Phone Scanner Results: {result}")

    def test_email_scanner(self):
        """Test email intelligence gathering"""
        print("\nTesting Email Scanner...")
        scanner = self.scanners["email"]
        result = scanner.gather_intelligence(self.test_data["email"], "emailrep")
        
        self.assertIsInstance(result, dict)
        self.assertIn("validation", result)
        self.assertIn("reputation_score", result)
        print(f"Email Scanner Results: {result}")

    def test_breach_scanner(self):
        """Test breach intelligence gathering"""
        print("\nTesting Breach Scanner...")
        scanner = self.scanners["breach"]
        result = scanner.gather_intelligence(self.test_data["email"], "haveibeenpwned")
        
        self.assertIsInstance(result, dict)
        self.assertIn("breach_count", result)
        self.assertIn("exposed_data", result)
        self.assertIsInstance(result["exposed_data"], list)
        print(f"Breach Scanner Results: {result}")

    def test_domain_scanner(self):
        """Test domain intelligence gathering"""
        print("\nTesting Domain Scanner...")
        scanner = self.scanners["domain"]
        result = scanner.gather_intelligence(self.test_data["domain"], "whois")
        
        self.assertIsInstance(result, dict)
        self.assertIn("whois_data", result)
        self.assertIn("dns_records", result)
        print(f"Domain Scanner Results: {result}")

    def test_threat_scanner(self):
        """Test threat intelligence gathering"""
        print("\nTesting Threat Scanner...")
        scanner = self.scanners["threat"]
        result = scanner.gather_intelligence(self.test_data["domain"], "virustotal")
        
        self.assertIsInstance(result, dict)
        self.assertIn("threat_score", result)
        self.assertIn("indicators", result)
        print(f"Threat Scanner Results: {result}")

    def test_social_scanner(self):
        """Test social intelligence gathering"""
        print("\nTesting Social Scanner...")
        scanner = self.scanners["social"]
        result = scanner.gather_intelligence(self.test_data["username"], "socialscan")
        
        self.assertIsInstance(result, dict)
        self.assertIn("profiles", result)
        self.assertIn("activity_metrics", result)
        print(f"Social Scanner Results: {result}")

    def test_deep_scan_integration(self):
        """Test deep scan integration"""
        print("\nTesting Deep Scan Integration...")
        result = self.deep_scanner.deep_scan(self.test_data["email"])
        
        self.assertIsInstance(result, dict)
        self.assertIn("scan_metadata", result)
        self.assertIn("intelligence_data", result)
        self.assertIn("correlation_analysis", result)
        self.assertIn("risk_assessment", result)
        
        metadata = result["scan_metadata"]
        self.assertIn("scan_id", metadata)
        self.assertIn("timestamp", metadata)
        self.assertIn("target", metadata)
        self.assertEqual(metadata["target"], self.test_data["email"])
        
        print(f"Deep Scan Metadata: {metadata}")

    def test_error_handling(self):
        """Test error handling in scanners"""
        print("\nTesting Error Handling...")
        
        # Test with invalid input
        invalid_data = {
            "email": "not-an-email",
            "phone": "not-a-phone",
            "domain": "not-a-domain",
            "breach": "not-a-breach-target",
            "threat": "not-a-threat-target",
            "social": "not-a-social-profile"
        }
        
        for scanner_type, scanner in self.scanners.items():
            print(f"\nTesting {scanner_type} scanner error handling...")
            result = scanner.gather_intelligence(invalid_data[scanner_type], "test")
            
            self.assertIsInstance(result, dict)
            print(f"{scanner_type} Scanner Error Handling Results: {result}")

    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        print("\nTesting Rate Limiting...")
        scanner = self.scanners["email"]
        
        # Make multiple requests to trigger rate limiting
        results = []
        for _ in range(3):
            result = scanner.gather_intelligence(self.test_data["email"], "emailrep")
            results.append(result)
            
        self.assertTrue(all(isinstance(r, dict) for r in results))
        print(f"Rate Limiting Test Results: {results}")

def run_tests():
    """Run all test cases"""
    unittest.main(verbosity=2)

if __name__ == "__main__":
    run_tests()
