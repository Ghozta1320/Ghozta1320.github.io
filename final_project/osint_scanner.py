from typing import Dict, Any
from rich.console import Console
import json
from datetime import datetime
from core_scanner import CoreScanner
from advanced_scanner import AdvancedScanner
from specialized_scanner import SpecializedScanner

class OSINTScanner:
    """Enhanced OSINT Scanner with comprehensive intelligence gathering capabilities"""

    def __init__(self):
        self.console = Console()
        self.specialized_scanner = SpecializedScanner()
        self.results_cache = {}

    def scan(self, target: str, scan_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Execute intelligence gathering based on scan type
        
        Args:
            target: Target to analyze (email, domain, IP, crypto address, etc.)
            scan_type: Type of scan to perform (basic, comprehensive, or deep)
        """
        scan_id = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{target}"
        
        try:
            if scan_type == "basic":
                results = self._perform_basic_scan(target)
            elif scan_type == "comprehensive":
                results = self._perform_comprehensive_scan(target)
            else:  # deep scan
                results = self._perform_deep_scan(target)

            # Cache results
            self.results_cache[scan_id] = results
            
            # Save results to file
            self._save_results(scan_id, results)
            
            return {
                "scan_id": scan_id,
                "status": "success",
                "result": results
            }

        except Exception as e:
            error_result = {
                "scan_id": scan_id,
                "status": "error",
                "error": str(e),
                "error_type": type(e).__name__
            }
            self.console.print(f"[red]Error during scan: {str(e)}[/red]")
            return error_result

    def _perform_basic_scan(self, target: str) -> Dict[str, Any]:
        """Execute basic intelligence gathering"""
        scanner = CoreScanner()
        results = {
            "threat_intelligence": scanner.analyze_threat_intelligence(target),
            "dark_web_exposure": scanner.analyze_dark_web(target)
        }
        return results

    def _perform_comprehensive_scan(self, target: str) -> Dict[str, Any]:
        """Execute comprehensive intelligence gathering"""
        scanner = AdvancedScanner()
        return scanner.comprehensive_scan(target)

    def _perform_deep_scan(self, target: str) -> Dict[str, Any]:
        """Execute deep intelligence gathering"""
        return self.specialized_scanner.deep_scan(target)

    def _save_results(self, scan_id: str, results: Dict[str, Any]) -> None:
        """Save scan results to file"""
        try:
            from pathlib import Path
            
            # Create findings directory if it doesn't exist
            findings_dir = Path("findings/osint_scans")
            findings_dir.mkdir(parents=True, exist_ok=True)
            
            # Save results
            result_file = findings_dir / f"osint_scan_{scan_id}.json"
            with open(result_file, 'w') as f:
                json.dump(results, f, indent=2)
                
            self.console.print(f"[green]Results saved to {result_file}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]Error saving results: {str(e)}[/red]")

    def get_scan_history(self) -> Dict[str, Any]:
        """Retrieve scan history"""
        try:
            from pathlib import Path
            
            findings_dir = Path("findings/osint_scans")
            if not findings_dir.exists():
                return {"scans": []}
            
            scans = []
            for file in findings_dir.glob("osint_scan_*.json"):
                try:
                    with open(file) as f:
                        scan_data = json.load(f)
                        scans.append({
                            "id": file.stem.replace("osint_scan_", ""),
                            "timestamp": file.stem.split("_")[2],
                            "data": scan_data
                        })
                except Exception as e:
                    self.console.print(f"[red]Error reading {file}: {str(e)}[/red]")
            
            return {"scans": scans}
            
        except Exception as e:
            self.console.print(f"[red]Error retrieving scan history: {str(e)}[/red]")
            return {"scans": []}

    def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """Retrieve results for a specific scan"""
        # First check cache
        if scan_id in self.results_cache:
            return self.results_cache[scan_id]
        
        # If not in cache, try to load from file
        try:
            from pathlib import Path
            
            result_file = Path(f"findings/osint_scans/osint_scan_{scan_id}.json")
            if not result_file.exists():
                return {"error": "Scan not found"}
            
            with open(result_file) as f:
                return json.load(f)
                
        except Exception as e:
            self.console.print(f"[red]Error retrieving scan results: {str(e)}[/red]")
            return {"error": str(e)}

    def analyze_target(self, target: str) -> Dict[str, Any]:
        """
        Smart target analysis - determines best scan type based on target
        """
        target_type = self._identify_target_type(target)
        
        if target_type == "crypto_address":
            # Deep scan for crypto addresses to get maximum blockchain intelligence
            return self._perform_deep_scan(target)
        elif target_type in ["email", "domain", "ip"]:
            # Comprehensive scan for common cyber targets
            return self._perform_comprehensive_scan(target)
        else:
            # Basic scan for other target types
            return self._perform_basic_scan(target)

    def _identify_target_type(self, target: str) -> str:
        """Identify the type of target for analysis"""
        import re
        
        # Cryptocurrency address patterns
        crypto_patterns = {
            "bitcoin": r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$",
            "ethereum": r"^0x[a-fA-F0-9]{40}$",
            "ripple": r"^r[0-9a-zA-Z]{24,34}$"
        }
        
        # Email pattern
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        
        # Domain pattern
        domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        
        # IP address pattern
        ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        
        # Check patterns
        for crypto_type, pattern in crypto_patterns.items():
            if re.match(pattern, target):
                return "crypto_address"
        
        if re.match(email_pattern, target):
            return "email"
        elif re.match(domain_pattern, target):
            return "domain"
        elif re.match(ip_pattern, target):
            return "ip"
        
        return "unknown"

if __name__ == "__main__":
    scanner = OSINTScanner()
    
    # Example usage
    target = "example@domain.com"
    print(f"\nAnalyzing target: {target}")
    results = scanner.analyze_target(target)
    print(json.dumps(results, indent=2))
