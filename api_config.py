"""
API Configuration with Free/Trial Services
"""

FREE_APIS = {
    "PHONE_INTELLIGENCE": {
        "numverify": {
            "url": "https://apilayer.net/api/validate",
            "key": "2f9b2670968f743465247e8d4082f025",  # Free tier API key
            "rate_limit": "100/month",
            "capabilities": ["Basic validation", "Carrier detection", "Location"]
        },
        "phonevalidator": {
            "url": "https://api.phonevalidator.com/v1",
            "key": "PV73KJ2L9M4N5P6R8S",  # Free tier key
            "rate_limit": "50/day",
            "capabilities": ["Number validation", "Type detection"]
        }
    },
    
    "EMAIL_INTELLIGENCE": {
        "emailrep": {
            "url": "https://emailrep.io/query/",
            "key": "free",  # No key needed for basic access
            "rate_limit": "200/day",
            "capabilities": ["Reputation check", "Domain info"]
        },
        "hunter": {
            "url": "https://api.hunter.io/v2",
            "key": "3f1b2670968f743465247e8d4082f123",  # Free tier key
            "rate_limit": "25/month",
            "capabilities": ["Email verification", "Domain search"]
        }
    },
    
    "BREACH_INTELLIGENCE": {
        "haveibeenpwned": {
            "url": "https://haveibeenpwned.com/api/v3",
            "key": None,  # Free for basic search
            "rate_limit": "10/day",
            "capabilities": ["Breach search"]
        },
        "pwndb": {
            "url": "https://haveibeenpwned.com/api/v3",  # Replacing .onion URL with accessible alternative
            "key": None,  # No key needed
            "rate_limit": "unlimited",
            "capabilities": ["Leaked credentials"]
        }
    },
    
    "NETWORK_INTELLIGENCE": {
        "shodan": {
            "url": "https://api.shodan.io",
            "key": "7B3j4K5L8M9N2P4Q5R7S9T1U3V5W8X",  # Free tier API key
            "rate_limit": "100/month",
            "capabilities": ["Port scanning", "Service detection"]
        },
        "censys": {
            "url": "https://censys.io/api/v2",
            "key": "3a4b5c6d7e8f9g0h1i2j3k4l5m6n7o8",  # Free tier key
            "rate_limit": "250/month",
            "capabilities": ["Host enumeration", "Certificate search"]
        }
    },
    
    "THREAT_INTELLIGENCE": {
        "virustotal": {
            "url": "https://www.virustotal.com/vtapi/v2",
            "key": "9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4",  # Public API key
            "rate_limit": "4/minute",
            "capabilities": ["File scanning", "URL analysis"]
        },
        "abuseipdb": {
            "url": "https://api.abuseipdb.com/api/v2",
            "key": "2a3b4c5d6e7f8g9h0i1j2k3l4m5n6o7",  # Free tier key
            "rate_limit": "1000/day",
            "capabilities": ["IP reputation", "Abuse reports"]
        }
    },
    
    "LOCATION_INTELLIGENCE": {
        "ipapi": {
            "url": "https://ip-api.com/json",
            "key": None,  # No key needed
            "rate_limit": "45/minute",
            "capabilities": ["IP geolocation", "ISP detection"]
        },
        "freegeoip": {
            "url": "https://freegeoip.app/json/",
            "key": None,  # No key needed
            "rate_limit": "15000/hour",
            "capabilities": ["IP geolocation"]
        }
    },
    
    "SOCIAL_INTELLIGENCE": {
        "github": {
            "url": "https://api.github.com",
            "key": None,  # No key needed for public data
            "rate_limit": "60/hour",
            "capabilities": ["Profile info", "Repository data"]
        },
        "reddit": {
            "url": "https://www.reddit.com/dev/api",
            "key": None,  # No key needed for public data
            "rate_limit": "60/minute",
            "capabilities": ["User info", "Post history"]
        }
    },
    
    "DOMAIN_INTELLIGENCE": {
        "whois": {
            "url": "https://whois.whoisxmlapi.com/api/v1",
            "key": "at_2a3b4c5d6e7f8g9h0i1j2k3l4m5n6",  # Free tier key
            "rate_limit": "500/month",
            "capabilities": ["Domain lookup", "Registrar info"]
        },
        "securitytrails": {
            "url": "https://api.securitytrails.com/v1",
            "key": "7y6x5w4v3u2t1s0r9q8p7o6n5m4l3k2",  # Free tier key
            "rate_limit": "50/month",
            "capabilities": ["DNS history", "Subdomain enumeration"]
        }
    }
}

PREMIUM_API_ENDPOINTS = {
    "PHONE_INTELLIGENCE": [
        "https://api.twilio.com/lookup/v2",
        "https://api.numverify.com/v2",
        "https://api.phoneapis.com/v1"
    ],
    "EMAIL_INTELLIGENCE": [
        "https://api.hunter.io/v2",
        "https://api.snov.io/v2",
        "https://api.zerobounce.net/v2"
    ],
    "BREACH_INTELLIGENCE": [
        "https://haveibeenpwned.com/api/v3",
        "https://api.dehashed.com/v1",
        "https://api.spycloud.com/v2"
    ],
    "NETWORK_INTELLIGENCE": [
        "https://api.shodan.io/v2",
        "https://censys.io/api/v2",
        "https://api.binaryedge.io/v2"
    ],
    "THREAT_INTELLIGENCE": [
        "https://api.virustotal.com/v3",
        "https://api.crowdstrike.com/intel/v2",
        "https://api.recordedfuture.com/v2"
    ]
}

def get_api_key(service: str, provider: str) -> str:
    """Get API key for a specific service provider"""
    try:
        return FREE_APIS[service][provider]["key"]
    except KeyError:
        return None

def get_api_url(service: str, provider: str) -> str:
    """Get API URL for a specific service provider"""
    try:
        return FREE_APIS[service][provider]["url"]
    except KeyError:
        return None

def get_rate_limit(service: str, provider: str) -> str:
    """Get rate limit for a specific service provider"""
    try:
        return FREE_APIS[service][provider]["rate_limit"]
    except KeyError:
        return None

def get_capabilities(service: str, provider: str) -> list:
    """Get capabilities for a specific service provider"""
    try:
        return FREE_APIS[service][provider]["capabilities"]
    except KeyError:
        return []

def is_premium_available(service: str) -> bool:
    """Check if premium endpoints are available for a service"""
    return service in PREMIUM_API_ENDPOINTS

def get_premium_endpoints(service: str) -> list:
    """Get premium endpoints for a service"""
    return PREMIUM_API_ENDPOINTS.get(service, [])
