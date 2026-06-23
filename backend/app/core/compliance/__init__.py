"""Compliance control catalog and evaluation.

Maps SDPP's technical controls to industry frameworks (OWASP ASVS, NIST CSF,
NIST cryptography standards, ISO/IEC 27001). The :mod:`controls` module is the
machine-readable source of truth used by the Compliance Service to generate
scored reports.
"""

from app.core.compliance.controls import CONTROLS, Control, controls_for_framework

__all__ = ["CONTROLS", "Control", "controls_for_framework"]
