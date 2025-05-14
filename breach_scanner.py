"""
Breach Intelligence Scanner Implementation
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from rich.console import Console
from scanner_core import ScannerCore

class BreachScanner(ScannerCore):
    """Specialized scanner for breach intelligence gathering"""

    def __init__(self):
        super().__init__()
        self.console = Console()

    def gather_intelligence(self, target: str, provider: str) -> Dict[str, Any]:
        """
        Gather breach intelligence data
        
        Args:
            target: Target identifier (email, domain, etc.)
            provider: API provider to use
        """
        try:
            results = {
                "breach_count": 0,
                "exposed_data": [],
                "breach_details": [],
                "password_exposures": [],
                "risk_level": "LOW",
                "earliest_breach": None,
                "latest_breach": None,
                "affected_services": []
            }

            # Basic breach search
            breaches = self.api_manager.make_request(
                service="BREACH_INTELLIGENCE",
                provider=provider,
                endpoint="breachedaccount",
                params={"account": target}
            )

            if breaches:
                if isinstance(breaches, list):
                    results["breach_details"] = breaches
                    results["breach_count"] = len(breaches)
                elif isinstance(breaches, dict):
                    results["breach_details"] = [breaches]
                    results["breach_count"] = 1

                # Process breach details
                data_types = set()
                services = set()
                dates = []

                for breach in results["breach_details"]:
                    # Handle different API response formats
                    if isinstance(breach, dict):
                        # Extract dates
                        breach_date = breach.get("BreachDate") or breach.get("breach_date")
                        if breach_date:
                            dates.append(breach_date)

                        # Extract data types
                        data_classes = breach.get("DataClasses") or breach.get("data_classes") or []
                        if isinstance(data_classes, (list, set)):
                            data_types.update(data_classes)
                        elif isinstance(data_classes, str):
                            data_types.add(data_classes)

                        # Extract services
                        service = breach.get("Name") or breach.get("service") or breach.get("domain")
                        if service:
                            services.add(service)

                # Update results
                results["exposed_data"] = sorted(list(data_types))
                results["affected_services"] = sorted(list(services))

                if dates:
                    results["earliest_breach"] = min(dates)
                    results["latest_breach"] = max(dates)

                # Set risk level based on findings
                if results["breach_count"] > 5:
                    results["risk_level"] = "HIGH"
                elif results["breach_count"] > 2:
                    results["risk_level"] = "MEDIUM"

            # Try to get additional password exposure data
            password_data = self.api_manager.make_request(
                service="BREACH_INTELLIGENCE",
                provider=provider,
                endpoint="passwords",
                params={"account": target}
            )
            if password_data:
                results["password_exposures"] = password_data.get("exposures", [])

            return results

        except Exception as e:
            self.console.print(f"[red]Error in breach intelligence gathering: {str(e)}[/red]")
            return {
                "breach_count": 0,
                "exposed_data": [],
                "breach_details": [],
                "password_exposures": [],
                "risk_level": "UNKNOWN",
                "earliest_breach": None,
                "latest_breach": None,
                "affected_services": []
            }

    def analyze_breaches(self, breaches: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze breach data for patterns and risks
        
        Args:
            breaches: List of breach records
        """
        analysis = {
            "severity_distribution": {},
            "data_type_frequency": {},
            "temporal_pattern": {},
            "risk_factors": []
        }

        if not breaches:
            return analysis

        # Analyze severity distribution
        for breach in breaches:
            severity = breach.get("severity", "unknown").lower()
            analysis["severity_distribution"][severity] = \
                analysis["severity_distribution"].get(severity, 0) + 1

        # Analyze exposed data types
        for breach in breaches:
            data_types = breach.get("DataClasses", [])
            for dtype in data_types:
                analysis["data_type_frequency"][dtype] = \
                    analysis["data_type_frequency"].get(dtype, 0) + 1

        # Analyze temporal patterns
        for breach in breaches:
            date = breach.get("BreachDate")
            if date:
                year = date[:4]  # Extract year from date
                analysis["temporal_pattern"][year] = \
                    analysis["temporal_pattern"].get(year, 0) + 1

        # Identify risk factors
        sensitive_data_types = {
            "Passwords", "Credit Cards", "Social Security Numbers",
            "Bank Accounts", "Health Records"
        }
        
        for data_type in sensitive_data_types:
            if data_type in analysis["data_type_frequency"]:
                analysis["risk_factors"].append({
                    "type": "sensitive_data_exposure",
                    "details": f"Exposed {data_type}",
                    "severity": "HIGH"
                })

        return analysis

    def get_risk_metrics(self, results: Dict[str, Any]) -> Dict[str, float]:
        """
        Calculate risk metrics from breach data
        
        Args:
            results: Breach intelligence results
        """
        metrics = {
            "overall_risk_score": 0.0,
            "data_sensitivity_score": 0.0,
            "breach_frequency_score": 0.0,
            "temporal_risk_score": 0.0
        }

        if not results or not results.get("breach_details"):
            return metrics

        # Calculate breach frequency score
        breach_count = results["breach_count"]
        metrics["breach_frequency_score"] = min(1.0, breach_count / 10.0)

        # Calculate data sensitivity score
        sensitive_data_types = {
            "Passwords": 0.8,
            "Credit Cards": 1.0,
            "Social Security Numbers": 1.0,
            "Bank Accounts": 1.0,
            "Health Records": 0.9,
            "Phone Numbers": 0.4,
            "Email Addresses": 0.3
        }

        sensitivity_scores = []
        for data_type in results["exposed_data"]:
            if data_type in sensitive_data_types:
                sensitivity_scores.append(sensitive_data_types[data_type])
        
        if sensitivity_scores:
            metrics["data_sensitivity_score"] = max(sensitivity_scores)

        # Calculate temporal risk score (more recent breaches = higher risk)
        if results["latest_breach"]:
            try:
                latest_year = int(results["latest_breach"][:4])
                current_year = datetime.now().year
                years_since_breach = current_year - latest_year
                metrics["temporal_risk_score"] = max(0.0, 1.0 - (years_since_breach * 0.1))
            except (ValueError, TypeError):
                metrics["temporal_risk_score"] = 0.5

        # Calculate overall risk score
        weights = {
            "breach_frequency": 0.3,
            "data_sensitivity": 0.4,
            "temporal_risk": 0.3
        }

        metrics["overall_risk_score"] = (
            weights["breach_frequency"] * metrics["breach_frequency_score"] +
            weights["data_sensitivity"] * metrics["data_sensitivity_score"] +
            weights["temporal_risk"] * metrics["temporal_risk_score"]
        )

        return metrics

if __name__ == "__main__":
    # Example usage
    scanner = BreachScanner()
    results = scanner.gather_intelligence("test@example.com", "haveibeenpwned")
    print(results)
