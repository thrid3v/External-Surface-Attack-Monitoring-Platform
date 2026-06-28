"""
constants.py
------------
Shared constants used across the API layer.
Import from here rather than defining locally in routers or workers.
"""

# Canonical execution order for scanner modules.
# Both the router (for progress display) and the worker (for execution)
# must reference this single list so they never drift out of sync.
MODULE_ORDER: list[str] = [
    "port_scanner",
    "cve_lookup",
    "dns_enum",
    "osint_fetcher",
    "service_probe",
    "web_audit",
    "web_vuln_probe",
    "secret_scan",
    "takeover_check",
    "email_audit",
    "nuclei_scan",
]

# Named port profiles so the UI/API can offer presets instead of raw nmap
# port strings. A request may still pass an explicit `port_range` to override.
PORT_PROFILES: dict[str, str] = {
    "common": "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8000,8080,8443",
    "top-1000": "1-1000",
    "full": "1-65535",
}
DEFAULT_PORT_PROFILE: str = "top-1000"
