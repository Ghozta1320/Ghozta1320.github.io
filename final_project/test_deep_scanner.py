"""
Test Suite for Deep Intelligence Scanner
"""

import unittest
from deep_scanner import DeepScanner
from api_manager import APIManager
from api_config import FREE_APIS
import json
from datetime import datetime

class TestDeepScanner(unittest.TestCase):
    """Test cases for Deep Intelligence Scanner"""

    def setUp(self):
        self.scanner = DeepScanner()
        self.test_email = "test@example.com"
        self.test_phone = "+1234567890"
        self.test_domain = "example.com"

    def test_email_scan(self):
        """Test email intelligence gathering"""
        print("\nTesting Email Intelligence Gathering...")
        results = self.scanner.deep_scan(self.test_email, ["EMAIL_INTELLIGENCE"])
        
        self.assertIn("intelligence_data", results)
        self.assertIn("EMAIL_INTELLIGENCE", results["intelligence_data"])
        
        email_data = results["intelligence_data"]["EMAIL_INTELLIGENCE"]
        self.assertIsInstance(email_data, dict)
        
        # Print results for manual verification
        print(json.dumps(email_data, indent=2))

    def test_phone_scan(self):
        """Test phone intelligence gathering"""
        print("\nTesting Phone Intelligence Gathering...")
        results = self.scanner.deep_scan(self.test_phone, ["PHONE_INTELLIGENCE"])
        
        self.assertIn("intelligence_data", results)
        self.assertIn("PHONE_INTELLIGENCE", results["intelligence_data"])
        
        phone_data = results["intelligence_data"]["PHONE_INTELLIGENCE"]
        self.assertIsInstance(phone_data, dict)
        
        print(json.dumps(phone_data, indent=2))

    def test_domain_scan(self):
        """Test domain intelligence gathering"""
        print("\nTesting Domain Intelligence Gathering...")
        results = self.scanner.deep_scan(self.test_domain, ["DOMAIN_INTELLIGENCE"])
        
        self.assertIn("intelligence_data", results)
        self.assertIn("DOMAIN_INTELLIGENCE", results["intelligence_data"])
        
        domain_data = results["intelligence_data"]["DOMAIN_INTELLIGENCE"]
        self.assertIsInstance(domain_data, dict)
        
        print(json.dumps(domain_data, indent=2))

    def test_breach_scan(self):
        """Test breach intelligence gathering"""
        print("\nTesting Breach Intelligence Gathering...")
        results = self.scanner.deep_scan(self.test_email, ["BREACH_INTELLIGENCE"])
        
        self.assertIn("intelligence_data", results)
        self.assertIn("BREACH_INTELLIGENCE", results["intelligence_data"])
        
        breach_data = results["intelligence_data"]["BREACH_INTELLIGENCE"]
        self.assertIsInstance(breach_data, dict)
        
        print(json.dumps(breach_data, indent=2))

    def test_correlation_analysis(self):
        """Test correlation analysis"""
        print("\nTesting Correlation Analysis...")
        results = self.scanner.deep_scan(self.test_email)
        
        self.assertIn("correlation_analysis", results)
        correlation_data = results["correlation_analysis"]
        
        # Verify correlation components
        self.assertIn("identity_correlations", correlation_data)
        self.assertIn("behavioral_patterns", correlation_data)
        self.assertIn("temporal_analysis", correlation_data)
        
        print(json.dumps(correlation_data, indent=2))

    def test_risk_assessment(self):
        """Test risk assessment calculation"""
        print("\nTesting Risk Assessment...")
        results = self.scanner.deep_scan(self.test_email)
        
        self.assertIn("risk_assessment", results)
        risk_data = results["risk_assessment"]
        
        # Verify risk assessment components
        self.assertIn("overall_risk_score", risk_data)
        self.assertIsInstance(risk_data["overall_risk_score"], float)
        self.assertGreaterEqual(risk_data["overall_risk_score"], 0.0)
        self.assertLessEqual(risk_data["overall_risk_score"], 1.0)
        
        print(json.dumps(risk_data, indent=2))

    def test_api_fallback(self):
        """Test API fallback mechanism"""
        print("\nTesting API Fallback Mechanism...")
        api_manager = APIManager()
        
        # Test with each category
        for category in FREE_APIS.keys():
            print(f"\nTesting fallback for {category}...")
            
            # Get initial provider
            provider = api_manager.get_best_provider(category)
            self.assertIsNotNone(provider)
            print(f"Initial provider: {provider}")
            
            # Get alternative provider
            alt_provider = api_manager._get_alternative_provider(category, provider)
            print(f"Alternative provider: {alt_provider}")
            
            if len(FREE_APIS[category]) > 1:
                self.assertIsNotNone(alt_provider)
                self.assertNotEqual(provider, alt_provider)

    def test_comprehensive_scan(self):
        """Test comprehensive scanning with all intelligence types"""
        print("\nTesting Comprehensive Scan...")
        results = self.scanner.deep_scan(self.test_email)
        
        # Verify all components are present
        self.assertIn("scan_metadata", results)
        self.assertIn("intelligence_data", results)
        self.assertIn("correlation_analysis", results)
        self.assertIn("risk_assessment", results)
        self.assertIn("recommendations", results)
        
        # Verify scan metadata
        metadata = results["scan_metadata"]
        self.assertIn("scan_id", metadata)
        self.assertIn("timestamp", metadata)
        self.assertIn("target", metadata)
        self.assertEqual(metadata["target"], self.test_email)
        
        print(json.dumps(results, indent=2))

def run_tests():
    """Run all test cases"""
    unittest.main(verbosity=2)

if __name__ == "__main__":
    run_tests()
