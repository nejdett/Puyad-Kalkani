from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parent.parent))
import schemas

RULE: dict[str, Any] = {
    "id": "x.1", "name": "Kural", "category": "ssh", "severity": "high",
    "check_command": "true", "fix_command": "true", "description": "",
}


@pytest.mark.parametrize("model,fields", [
    (schemas.RuleModel, {**RULE, "check_command": "a" * 4097}),
    (schemas.RuleModel, {**RULE, "description": "a" * 2001}),
    (schemas.LoginModel, {"username": "a" * 65, "password": "x"}),
    (schemas.LoginModel, {"username": "admin", "password": "a" * 257}),
    (schemas.ServerModel, {"name": "a" * 257, "ip_address": "10.0.0.1"}),
    (schemas.AgentHeartbeatModel, {"hostname": "a" * 257}),
    (schemas.CveBatchFixModel, {"packages": ["p"] * 501}),
    (schemas.CveBatchFixModel, {"packages": ["a" * 257]}),
])
def test_oversized_fields_rejected(model: type[Any], fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        model(**fields)


def test_limits_fit_builtin_rules() -> None:
    import engine

    for rule in engine.load_rules():
        schemas.RuleModel(**{k: rule.get(k) or "" for k in RULE})


def test_normal_values_accepted() -> None:
    schemas.RuleModel(**RULE)
    schemas.AgentHeartbeatModel(hostname="web-1", status="online")
    schemas.CveBatchFixModel(packages=["openssl", "libc6"])
