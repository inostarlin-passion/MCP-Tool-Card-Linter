from __future__ import annotations

import hashlib
from typing import Any

from .rules import KNOWN_RULE_IDS, RULE_CATALOG_VERSION

# v1.0 public compatibility contract. These values are machine-readable through
# `mcp-tool-card-linter contract` and are intentionally changed only according
# to the compatibility policy documented in README.md.
CONTRACT_VERSION = "1.0.0"
CURRENT_REPORT_SCHEMA_VERSION = "1.1.0"
SUPPORTED_REPORT_SCHEMA_VERSIONS = ("1.0.0", CURRENT_REPORT_SCHEMA_VERSION)

CURRENT_MCP_PROTOCOL_VERSION = "2025-11-25"
PREVIOUS_MCP_PROTOCOL_VERSION = "2025-06-18"
LEGACY_MCP_PROTOCOL_VERSIONS = ("2025-03-26",)
SUPPORTED_MCP_PROTOCOL_VERSIONS = (
    CURRENT_MCP_PROTOCOL_VERSION,
    PREVIOUS_MCP_PROTOCOL_VERSION,
    *LEGACY_MCP_PROTOCOL_VERSIONS,
)

EXIT_SUCCESS = 0
EXIT_FINDINGS = 1
EXIT_OPERATIONAL_ERROR = 2
EXIT_INTERRUPTED = 130
CLI_EXIT_CODES = {
    "success": EXIT_SUCCESS,
    "findings_at_or_above_threshold": EXIT_FINDINGS,
    "operational_or_input_error": EXIT_OPERATIONAL_ERROR,
    "interrupted": EXIT_INTERRUPTED,
}


def public_contract() -> dict[str, Any]:
    """Return the bounded, deterministic v1 public compatibility contract."""
    rule_ids = list(KNOWN_RULE_IDS)
    digest = hashlib.sha256(("\n".join(rule_ids) + "\n").encode()).hexdigest()
    return {
        "contract_version": CONTRACT_VERSION,
        "report_schemas": {
            "current": CURRENT_REPORT_SCHEMA_VERSION,
            "readable": list(SUPPORTED_REPORT_SCHEMA_VERSIONS),
            "compatibility": "additive-within-major",
        },
        "rule_catalog": {
            "version": RULE_CATALOG_VERSION,
            "ids": rule_ids,
            "ids_sha256": digest,
            "removal_policy": "deprecate-before-major",
        },
        "cli": {
            "exit_codes": dict(CLI_EXIT_CODES),
            "removal_policy": "deprecate-before-major",
        },
        "mcp_protocols": {
            "current": CURRENT_MCP_PROTOCOL_VERSION,
            "previous": PREVIOUS_MCP_PROTOCOL_VERSION,
            "supported": list(SUPPORTED_MCP_PROTOCOL_VERSIONS),
            "legacy": list(LEGACY_MCP_PROTOCOL_VERSIONS),
        },
    }
