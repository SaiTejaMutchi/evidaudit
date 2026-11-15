"""Zero-dependency declarative YAML test-case runner for EvidAudit."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from evidaudit.auditor import Auditor


@dataclass(frozen=True)
class YamlTestResult:
    name: str
    passed: bool
    decision: str
    concealed_corruption: bool
    semantic_errors: list[dict[str, str]]
    transitions: list[dict[str, Any]]
    failures: list[str]


def _parse_scalar(raw: str) -> Any:
    val = raw.strip()
    if not val:
        return ""
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        return val[1:-1]
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part) for part in inner.split(",")]
    if val.lower() == "true":
        return True
    if val.lower() == "false":
        return False
    if val.lower() in ("null", "none", "~"):
        return None
    try:
        return int(val)
    except ValueError:
        return val


def parse_simple_yaml(text: str) -> Any:
    """Parse JSON or a clean indentation-based subset of YAML without third-party packages."""
    stripped = text.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        return json.loads(stripped)

    lines: list[tuple[int, str]] = []
    for raw_line in text.splitlines():
        no_comment = raw_line.split("#", 1)[0].rstrip()
        if not no_comment.strip():
            continue
        indent = len(no_comment) - len(no_comment.lstrip(" "))
        lines.append((indent, no_comment.strip()))

    def parse_block(idx: int, min_indent: int) -> tuple[Any, int]:
        if idx >= len(lines):
            return {}, idx
        indent, content = lines[idx]
        if content.startswith("- "):
            arr: list[Any] = []
            while idx < len(lines) and lines[idx][0] == indent and lines[idx][1].startswith("- "):
                item_text = lines[idx][1][2:].strip()
                if ":" in item_text and not item_text.startswith("{"):
                    k, v = item_text.split(":", 1)
                    obj: dict[str, Any] = {}
                    v_s = v.strip()
                    if v_s:
                        obj[k.strip()] = _parse_scalar(v_s)
                        idx += 1
                    else:
                        idx += 1
                        sub_val, idx = parse_block(idx, indent + 2)
                        obj[k.strip()] = sub_val
                    if idx < len(lines) and lines[idx][0] > indent and not lines[idx][1].startswith("- "):
                        extra, idx = parse_block(idx, indent + 2)
                        if isinstance(extra, dict):
                            obj.update(extra)
                    arr.append(obj)
                else:
                    arr.append(_parse_scalar(item_text))
                    idx += 1
            return arr, idx

        mapping: dict[str, Any] = {}
        while idx < len(lines) and lines[idx][0] >= min_indent:
            cur_indent, cur_content = lines[idx]
            if cur_indent != indent or cur_content.startswith("- "):
                break
            if ":" not in cur_content:
                raise ValueError(f"Invalid YAML line: {cur_content}")
            k, v = cur_content.split(":", 1)
            key = k.strip()
            v_s = v.strip()
            if v_s:
                mapping[key] = _parse_scalar(v_s)
                idx += 1
            else:
                idx += 1
                sub_val, idx = parse_block(idx, cur_indent + 1)
                mapping[key] = sub_val
        return mapping, idx

    parsed, _ = parse_block(0, 0)
    return parsed


def run_yaml_test_case(path: str | Path) -> YamlTestResult:
    """Load and execute a declarative YAML policy & evidence regression test case."""
    spec = parse_simple_yaml(Path(path).read_text(encoding="utf-8"))
    if not isinstance(spec, dict):
        raise ValueError(f"Test file {path} must define a YAML mapping.")

    name = str(spec.get("name", Path(path).name))
    evidence = dict(spec.get("evidence", {}))
    if "packet_ids" in evidence and isinstance(evidence["packet_ids"], list):
        evidence["packet_ids"] = set(evidence["packet_ids"])

    propositions = spec.get("propositions", {})
    auditor = Auditor(variant=str(spec.get("variant", "v2-strict")))
    res = auditor.evaluate(propositions=propositions, evidence=evidence)

    failures: list[str] = []
    if "expected_decision" in spec and res.decision != spec["expected_decision"]:
        failures.append(f"expected_decision={spec['expected_decision']} got={res.decision}")
    if "expected_concealed_corruption" in spec and res.concealed_corruption != bool(spec["expected_concealed_corruption"]):
        failures.append(
            f"expected_concealed_corruption={spec['expected_concealed_corruption']} got={res.concealed_corruption}"
        )

    transitions_out: list[dict[str, Any]] = []
    for tr in spec.get("transitions", []):
        if tr.get("type") == "override_revocation":
            exp = auditor.test_override_revocation(
                propositions=propositions,
                target_prohibition=str(tr["target_prohibition"]),
                prohibition_id=str(tr["prohibition_id"]),
                packet_ids=evidence.get("packet_ids"),
            )
            tr_record = {
                "type": "override_revocation",
                "post_transition_decision": exp.post_transition_decision,
                "unsafe_approval_exposed": exp.unsafe_approval_exposed,
                "repaired_decision": exp.repaired_decision,
                "repair_restored_safety": exp.repair_restored_safety,
            }
            transitions_out.append(tr_record)
            if "expected_post_transition_decision" in tr and exp.post_transition_decision != tr["expected_post_transition_decision"]:
                failures.append(
                    f"transition post_decision expected={tr['expected_post_transition_decision']} got={exp.post_transition_decision}"
                )
            if "expected_repaired_decision" in tr and exp.repaired_decision != tr["expected_repaired_decision"]:
                failures.append(
                    f"transition repaired_decision expected={tr['expected_repaired_decision']} got={exp.repaired_decision}"
                )

    return YamlTestResult(
        name=name,
        passed=(len(failures) == 0),
        decision=res.decision,
        concealed_corruption=res.concealed_corruption,
        semantic_errors=[
            {
                "section": e.section,
                "item_id": e.item_id,
                "extracted": e.extracted_state,
                "reference": e.reference_state,
            }
            for e in res.semantic_errors
        ],
        transitions=transitions_out,
        failures=failures,
    )
