#!/usr/bin/env python3
import argparse
import ipaddress
import json
import sys
from pathlib import Path


FIELD_MAP = {
    "domain": "DOMAIN",
    "domain_suffix": "DOMAIN-SUFFIX",
    "domain_keyword": "DOMAIN-KEYWORD",
    "domain_regex": "DOMAIN-REGEX",
    "ip_cidr": "IP-CIDR",
    "source_ip_cidr": "SRC-IP-CIDR",
    "port": "DST-PORT",
    "source_port": "SRC-PORT",
    "process_name": "PROCESS-NAME",
    "process_name_regex": "PROCESS-NAME-REGEX",
    "process_path": "PROCESS-PATH",
    "process_path_regex": "PROCESS-PATH-REGEX",
    "package_name": "PROCESS-NAME",
}


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize_value(field, value):
    value = str(value)
    if field == "domain_suffix":
        return value.lstrip(".")
    if field in {"ip_cidr", "source_ip_cidr"}:
        if "/" in value:
            return value
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return value
        return f"{value}/{'128' if ip.version == 6 else '32'}"
    return value


def make_line(rule_type, value):
    return f"{rule_type},{value}"


def logical_expr(mode, children):
    op = mode.upper()
    return f"{op},(" + ",".join(f"({child})" for child in children) + ")"


def rule_field_exprs(rule):
    expressions = []
    for field, mihomo_type in FIELD_MAP.items():
        values = [
            make_line(mihomo_type, normalize_value(field, value))
            for value in as_list(rule.get(field))
        ]
        if len(values) == 1:
            expressions.append(values[0])
        elif len(values) > 1:
            expressions.append(logical_expr("or", values))
    return expressions


def rule_to_expr(rule):
    if not isinstance(rule, dict):
        raise ValueError("rule must be an object")

    rule_type = rule.get("type")
    if rule_type == "logical":
        mode = rule.get("mode")
        if mode not in {"and", "or"}:
            raise ValueError(f"unsupported logical mode: {mode}")
        expressions = [rule_to_expr(child) for child in rule.get("rules", [])]
        if not expressions:
            raise ValueError("empty logical rule")
        expr = expressions[0] if len(expressions) == 1 else logical_expr(mode, expressions)
    else:
        expressions = rule_field_exprs(rule)
        if not expressions:
            meaningful_keys = set(rule) - {"type", "invert"}
            if meaningful_keys:
                raise ValueError(f"unsupported rule fields: {', '.join(sorted(meaningful_keys))}")
            raise ValueError("empty rule")
        expr = expressions[0] if len(expressions) == 1 else logical_expr("and", expressions)

    if rule.get("invert"):
        return logical_expr("not", [expr])
    return expr


def add_payload(payload, seen, line):
    if line not in seen:
        payload.append(line)
        seen.add(line)


def collect_top_level(rule, payload, seen):
    if (
        isinstance(rule, dict)
        and not rule.get("invert")
        and rule.get("type") == "logical"
        and rule.get("mode") == "or"
    ):
        for child in rule.get("rules", []):
            collect_top_level(child, payload, seen)
        return

    if isinstance(rule, dict) and not rule.get("invert") and rule.get("type") != "logical":
        expressions = rule_field_exprs(rule)
        if len(expressions) == 1 and expressions[0].startswith("OR,(("):
            for value in as_list(next(rule[field] for field in FIELD_MAP if field in rule)):
                field = next(field for field in FIELD_MAP if field in rule)
                add_payload(
                    payload,
                    seen,
                    make_line(FIELD_MAP[field], normalize_value(field, value)),
                )
            return

    add_payload(payload, seen, rule_to_expr(rule))


def yaml_quote(value):
    return json.dumps(value, ensure_ascii=False)


def convert(source, target):
    data = json.loads(source.read_text(encoding="utf-8"))
    payload = []
    seen = set()

    for rule in data.get("rules", []):
        collect_top_level(rule, payload, seen)

    if not payload:
        raise ValueError("empty YAML payload")

    body = "payload:\n" + "".join(f"  - {yaml_quote(item)}\n" for item in payload)
    target.write_text(body, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("target", type=Path)
    args = parser.parse_args()

    try:
        convert(args.source, args.target)
    except Exception as exc:
        print(f"{args.source}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
