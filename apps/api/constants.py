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
]
