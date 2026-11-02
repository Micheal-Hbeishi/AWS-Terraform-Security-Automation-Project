"""Offline demonstration. No AWS credentials or third-party packages needed."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from automation.security_audit import exposed_ports

rules = json.loads((ROOT / "examples/security-group-rules.json").read_text())
print(json.dumps([
    {"rule_id": rule["SecurityGroupRuleId"], "exposed_ports": exposed_ports(rule)}
    for rule in rules if exposed_ports(rule)
], indent=2))
