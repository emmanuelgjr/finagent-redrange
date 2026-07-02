"""Handout exporters — turn a range run's Findings into ready-to-use artifacts.

Each exporter consumes the same ``list[Finding]`` the scorecard receives (no coupling to
``target/`` or ``attacker/``) and writes an artifact a security team can pick up directly:

  * :mod:`~finagent_redrange.exports.sigma`     — portable Sigma detection rules + a measured
    labeled-replay precision report (for detection/SOC engineers).
  * :mod:`~finagent_redrange.exports.sarif`      — a SARIF 2.1.0 findings run carrying the
    OWASP/ATLAS/NIST crosswalk as taxonomies (for devsecops tooling).
  * :mod:`~finagent_redrange.exports.assurance`  — a GSN-style control-effectiveness assurance
    case bound to the range's own tests + transcript hashes (for AI security architects / GRC).
  * :mod:`~finagent_redrange.exports.compliance` — a regulatory control crosswalk (NIST AI RMF +
    GenAI Profile, ISO/IEC 42001, EU AI Act), with declared-vs-interpretive provenance labeling.
"""

from __future__ import annotations

from finagent_redrange.exports.assurance import write_assurance
from finagent_redrange.exports.compliance import write_compliance
from finagent_redrange.exports.sarif import write_sarif
from finagent_redrange.exports.sigma import write_sigma

__all__ = ["write_assurance", "write_compliance", "write_sarif", "write_sigma"]
