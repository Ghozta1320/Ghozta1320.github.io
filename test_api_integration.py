"""
API Integration Tests for Intelligence Scanners
Tests live API endpoints and edge cases
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

class TestAPIIntegration(unittest.TestCase):
    """Test cases for API integration"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_data = {
            "valid": {
                "email": "test@example.com",
                "phone": "+1234567890",
                "domain": "example.com",
                "username": "testuser"
            },
            "edge_cases": {
                "email": ["", "invalid@", "@nodomain", "test@test@test.com", "a"*100+"@test.com"],
                "phone": ["", "+", "123", "+" + "1"*20, "abc123"],
                "domain": ["", ".", "test", "a"*300+".com", "test..com"],
                "username": ["", " ", "a"*200, "test@user", "<script>alert(1)</script>"]
            },
            "malformed": {
                "email": None,
                "phone": {"number": "123"},
                "domain": ["test.com"],
                "username": 12345
            }
        }
        self.scanners = {
            "phone": PhoneScanner(),
            "email": EmailScanner(),
            "domain": DomainScanner(),
            "breach": BreachScanner(),
            "threat": ThreatScanner(),
            "social": SocialScanner()
        }

    def test_live_api_endpoints(self):
        """Test live API endpoint responses"""
        print("\nTesting Live API Endpoints...")
        
        for scanner_type, scanner in self.scanners.items():
            with self.subTest(scanner=scanner_type):
                target = self.test_data["valid"].get(
                    "email" if scanner_type in ["email", "breach"] else
                    "domain" if scanner_type in ["domain", "threat"] else
                    "username" if scanner_type == "social" else
                    "phone"
                )
                
                # Test with default provider
                result = scanner.gather_intelligence(target, None)
                self.assertIsInstance(result, dict)
                print(f"\n{scanner_type.title()} Scanner Live Test Results:")
                print(json.dumps(result, indent=2))

    def test_edge_cases(self):
        """Test edge case handling"""
        print("\nTesting Edge Cases...")
        
        for scanner_type, scanner in self.scanners.items():
            with self.subTest(scanner=scanner_type):
                # Test edge case inputs
                edge_cases = self.test_data["edge_cases"].get(
                    "email" if scanner_type in ["email", "breach"] else
                    "domain" if scanner_type in ["domain", "threat"] else
                    "username" if scanner_type == "social" else
                    "phone"
                )
                
                for test_input in edge_cases:
                    result = scanner.gather_intelligence(test_input, None)
                    self.assertIsInstance(result, dict)
                    print(f"\n{scanner_type.title()} Scanner Edge Case ({test_input}) Results:")
                    print(json.dumps(result, indent=2))

    def test_malformed_input(self):
        """Test handling of malformed input"""
        print("\nTesting Malformed Input...")
        
        for scanner_type, scanner in self.scanners.items():
            with self.subTest(scanner=scanner_type):
                malformed_input = self.test_data["malformed"].get(
                    "email" if scanner_type in ["email", "breach"] else
                    "domain" if scanner_type in ["domain", "threat"] else
                    "username" if scanner_type == "social" else
                    "phone"
                )
                
                result = scanner.gather_intelligence(malformed_input, None)
                self.assertIsInstance(result, dict)
                print(f"\n{scanner_type.title()} Scanner Malformed Input Results:")
                print(json.dumps(result, indent=2))

    def test_large_dataset(self):
        """Test performance with large datasets"""
        print("\nTesting Large Dataset Performance...")
        
        # Generate large test dataset
        large_dataset = {
            "email": [f"test{i}@example.com" for i in range(100)],
            "phone": [f"+1{str(i).zfill(10)}" for i in range(100)],
            "domain": [f"test{i}.example.com" for i in range(100)],
            "username": [f"testuser{i}" for i in range(100)]
        }
        
        for scanner_type, scanner in self.scanners.items():
            with self.subTest(scanner=scanner_type):
                dataset = large_dataset.get(
                    "email" if scanner_type in ["email", "breach"] else
                    "domain" if scanner_type in ["domain", "threat"] else
                    "username" if scanner_type == "social" else
                    "phone"
                )
                
                start_time = datetime.now()
                results = []
                
                for test_input in dataset[:10]:  # Test with first 10 items
                    result = scanner.gather_intelligence(test_input, None)
                    results.append(result)
                
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                
                self.assertTrue(all(isinstance(r, dict) for r in results))
                print(f"\n{scanner_type.title()} Scanner Performance:")
                print(f"Processed 10 items in {duration:.2f} seconds")
                print(f"Average time per item: {(duration/10):.2f} seconds")

def run_tests():
    """Run all test cases"""
    unittest.main(verbosity=2)

if __name__ == "__main__":
    run_tests()
