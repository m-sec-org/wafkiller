#!/usr/bin/env python3

from __future__ import annotations

import ast
import glob
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WAFDET_DIR = ROOT / "wafdet"
OUTPUT = ROOT / "waf.yaml"


@dataclass
class Condition:
    kind: str
    key: str = ""
    pattern: str = ""
    status: int = 0


@dataclass
class Rule:
    logic: str
    conditions: list[Condition]


@dataclass
class WAFRule:
    name: str
    rules: list[Rule]


def string_value(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    raise ValueError(f"unsupported string node: {ast.dump(node, include_attributes=False)}")


def int_value(node: ast.AST) -> int:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    raise ValueError(f"unsupported int node: {ast.dump(node, include_attributes=False)}")


def parse_header_arg(node: ast.AST) -> tuple[str, str]:
    if not isinstance(node, ast.Tuple) or len(node.elts) != 2:
        raise ValueError(f"unsupported header argument: {ast.dump(node, include_attributes=False)}")
    return string_value(node.elts[0]), string_value(node.elts[1])


def parse_condition(expr: ast.AST) -> Condition:
    if not isinstance(expr, ast.Call) or not isinstance(expr.func, ast.Attribute):
        raise ValueError(f"unsupported matcher call: {ast.dump(expr, include_attributes=False)}")
    method = expr.func.attr

    if method == "matchHeader":
        key, pattern = parse_header_arg(expr.args[0])
        return Condition(kind="header", key=key.lower(), pattern=pattern)
    if method == "matchCookie":
        return Condition(kind="cookie", pattern=string_value(expr.args[0]))
    if method == "matchContent":
        return Condition(kind="content", pattern=string_value(expr.args[0]))
    if method == "matchReason":
        return Condition(kind="reason", pattern=string_value(expr.args[0]))
    if method == "matchStatus":
        return Condition(kind="status", status=int_value(expr.args[0]))

    raise ValueError(f"unsupported matcher method: {method}")


def parse_list_assignment(node: ast.Assign) -> tuple[str, list[Condition]]:
    if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
        raise ValueError("unsupported assignment target")
    if not isinstance(node.value, ast.List):
        raise ValueError("unsupported assignment value")

    conditions = [parse_condition(item) for item in node.value.elts]
    return node.targets[0].id, conditions


def parse_if_logic(node: ast.If) -> tuple[str, str] | None:
    test = node.test
    if not isinstance(test, ast.Call) or not isinstance(test.func, ast.Name):
        return None
    if test.func.id not in {"any", "all"} or len(test.args) != 1:
        return None

    gen = test.args[0]
    if not isinstance(gen, ast.GeneratorExp):
        return None
    if len(gen.generators) != 1:
        return None
    comp = gen.generators[0]
    if not isinstance(comp.iter, ast.Name):
        return None

    return test.func.id, comp.iter.id


def dedupe_conditions(conditions: list[Condition]) -> list[Condition]:
    seen: set[tuple[str, str, str, int]] = set()
    deduped: list[Condition] = []
    for condition in conditions:
        key = (condition.kind, condition.key, condition.pattern, condition.status)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(condition)
    return deduped


def parse_waf_file(path: Path) -> WAFRule:
    tree = ast.parse(path.read_text(encoding="utf-8"), str(path))

    name = ""
    fn: ast.FunctionDef | None = None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "NAME":
                    name = string_value(node.value)
        elif isinstance(node, ast.FunctionDef) and node.name == "is_waf":
            fn = node

    if not name or fn is None:
        raise ValueError(f"missing NAME or is_waf in {path}")

    schemas: dict[str, list[Condition]] = {}
    rules: list[Rule] = []

    for stmt in fn.body:
        if isinstance(stmt, ast.Assign):
            schema_name, conditions = parse_list_assignment(stmt)
            schemas[schema_name] = dedupe_conditions(conditions)
            continue

        if isinstance(stmt, ast.If):
            parsed = parse_if_logic(stmt)
            if not parsed:
                continue
            logic, schema_name = parsed
            conditions = schemas.get(schema_name)
            if not conditions:
                continue
            rules.append(Rule(logic=logic, conditions=conditions))

    if not rules:
        raise ValueError(f"no rules extracted from {path}")

    return WAFRule(name=name, rules=rules)


def yaml_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def emit_rule(item: WAFRule) -> list[str]:
    lines = [f"- name: {yaml_quote(item.name)}", "  rule:"]
    for rule in item.rules:
        lines.append(f"    - logic: {rule.logic}")
        lines.append("      conditions:")
        for condition in rule.conditions:
            lines.append(f"        - type: {condition.kind}")
            if condition.key:
                lines.append(f"          key: {yaml_quote(condition.key)}")
            if condition.pattern:
                lines.append(f"          pattern: {yaml_quote(condition.pattern)}")
            if condition.kind == "status":
                lines.append(f"          status: {condition.status}")
    return lines


def main() -> None:
    items: list[WAFRule] = []
    for raw_path in sorted(glob.glob(str(WAFDET_DIR / "*.py"))):
        path = Path(raw_path)
        if path.name == "__init__.py":
            continue
        items.append(parse_waf_file(path))

    lines = [
        "# Auto-generated from wafdet Python rules.",
        "# Source: ./wafdet/*.py",
    ]
    for item in items:
        lines.extend(emit_rule(item))

    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"generated {len(items)} waf rules -> {OUTPUT}")


if __name__ == "__main__":
    main()
