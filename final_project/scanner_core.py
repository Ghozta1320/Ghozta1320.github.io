"""
Core Scanner Implementation
Handles basic scanning functionality and API integration
"""

from typing import Dict, Any, List, Optional
import json
from datetime import datetime
from rich.console import Console
from api_manager import APIManager
from api_config import FREE_APIS

class ScannerCore:
    """Core scanning functionality with API integration"""

    def __init__(self):
        self.console = Console()
        self.api_manager = APIManager()
        self.results_cache = {}

    def scan(self, target: str, scan_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Execute intelligence gathering scan
        
        Args:
            target: Target identifier (phone, email, domain, etc.)
            scan_types: List of intelligence categories to scan (None for all)
        """
        if not scan_types:
            scan_types = list(FREE_APIS.keys())

        scan_id = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{target}"
        
        results = {
            "scan_metadata": {
                "scan_id": scan_id,
                "timestamp": datetime.now().isoformat(),
                "target": target,
                "scan_types": scan_types
            },
            "intelligence_data": {},
            "risk_assessment": {},
            "correlation_analysis": {}
        }

        # Gather intelligence from each category
        for category in scan_types:
            try:
                provider = self.api_manager.get_best_provider(category)
                if provider:
                    data = self._gather_category_data(target, category, provider)
                    results["intelligence_data"][category] = data
            except Exception as e:
                self.console.print(f"[red]Error gathering {category} intelligence: {str(e)}[/red]")

        return results

    def _gather_category_data(self, target: str, category: str, provider: str) -> Dict[str, Any]:
        """Gather data for a specific intelligence category"""
        base_results = {
            "findings": [],
            "metadata": {},
            "risk_indicators": [],
            "confidence_scores": {}
        }

        try:
            # Basic data gathering
            data = self.api_manager.make_request(
                service=category,
                provider=provider,
                endpoint="query",
                params={"target": target}
            )

            if data:
                base_results["findings"].append({
                    "source": provider,
                    "timestamp": datetime.now().isoformat(),
                    "data": data
                })

            # Try enhanced data gathering if available
            enhanced_data = self.api_manager.make_request(
                service=category,
                provider=provider,
                endpoint="enhanced",
                params={"target": target}
            )

            if enhanced_data:
                base_results["findings"].append({
                    "source": f"{provider}_enhanced",
                    "timestamp": datetime.now().isoformat(),
                    "data": enhanced_data
                })

        except Exception as e:
            self.console.print(f"[red]Error with provider {provider}: {str(e)}[/red]")
            # Try alternative provider
            alt_provider = self.api_manager.rotate_provider(category, provider)
            if alt_provider:
                return self._gather_category_data(target, category, alt_provider)

        return base_results

    def get_scan_history(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get history of previous scans"""
        return {"scans": list(self.results_cache.values())}

    def get_scan_result(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get result of a specific scan"""
        return self.results_cache.get(scan_id)

if __name__ == "__main__":
    # Example usage
    scanner = ScannerCore()
    
    # Test scan
    target = "test@example.com"
    results = scanner.scan(target, ["EMAIL_INTELLIGENCE", "BREACH_INTELLIGENCE"])
    print(json.dumps(results, indent=2))
