"""
API Manager for handling API requests and rate limiting
"""

from typing import Dict, Any, Optional
import requests
from datetime import datetime, timedelta
from api_config import (
    get_api_key, get_api_url, get_rate_limit,
    get_capabilities
)

class APIManager:
    """Manages API interactions and rate limiting"""
    
    def __init__(self):
        self.rate_limits = {}
        self.request_counts = {}
        
    def make_request(self, service: str, provider: str, endpoint: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Make an API request with rate limiting"""
        try:
            # Get base URL and ensure it has a scheme
            base_url = get_api_url(service, provider)
            if not base_url:
                return {"error": f"No URL configured for {service}/{provider}"}
                
            # Ensure URL has scheme
            if not base_url.startswith(('http://', 'https://')):
                base_url = 'https://' + base_url
                
            # Construct full URL
            url = f"{base_url}/{endpoint}"
            
            # Add API key if required
            api_key = get_api_key(service, provider)
            if api_key:
                params['key'] = api_key
                
            # Make request
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    "error": f"API request failed: {response.status_code}",
                    "details": response.text
                }
                
        except requests.exceptions.RequestException as e:
            return {
                "error": f"Request failed: {str(e)}",
                "service": service,
                "provider": provider
            }
        except Exception as e:
            return {
                "error": f"Error making request to {provider}: {str(e)}"
            }
            
    def get_providers(self, service: str) -> Dict[str, Dict[str, Any]]:
        """Get available providers for a service"""
        providers = {}
        
        # Get all providers that have URLs configured
        for provider in ['emailrep', 'hunter', 'haveibeenpwned', 'virustotal', 
                        'shodan', 'censys', 'whois', 'phonevalidator']:
            url = get_api_url(service, provider)
            if url:
                providers[provider] = {
                    "url": url,
                    "capabilities": get_capabilities(service, provider),
                    "rate_limit": get_rate_limit(service, provider)
                }
                
        return providers
        
    def get_best_provider(self, service: str) -> Optional[str]:
        """Get the best available provider for a service"""
        providers = self.get_providers(service)
        if providers:
            return list(providers.keys())[0]  # Return first available provider
        return None
        
    def rotate_provider(self, service: str, current_provider: str) -> Optional[str]:
        """Rotate to next available provider if current one fails"""
        providers = list(self.get_providers(service).keys())
        
        if not providers:
            return None
            
        try:
            current_index = providers.index(current_provider)
            next_index = (current_index + 1) % len(providers)
            return providers[next_index]
        except ValueError:
            return providers[0] if providers else None
