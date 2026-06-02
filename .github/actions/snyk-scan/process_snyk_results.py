#!/usr/bin/env python3
import json
import os
import re
from pathlib import Path
from typing import Any


SARIF_PATH = Path("snyk-results.sarif")


def ensure_sarif_file() -> dict[str, Any]:
    if not SARIF_PATH.exists() or SARIF_PATH.stat().st_size == 0:
        doc: dict[str, Any] = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Snyk",
                            "rules": [],
                        }
                    },
                    "results": [],
                }
            ],
        }
        write_sarif(doc)
        return doc

    with SARIF_PATH.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        data = {"version": "2.1.0", "runs": []}

    return data


def write_sarif(doc: dict[str, Any]) -> None:
    with SARIF_PATH.open("w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


def ensure_primary_run(doc: dict[str, Any]) -> dict[str, Any]:
    runs = doc.get("runs")
    if not isinstance(runs, list) or len(runs) == 0:
        runs = []
    if len(runs) == 0:
        runs.append({})

    first = runs[0]
    if not isinstance(first, dict):
        first = {}

    tool = first.get("tool")
    if not isinstance(tool, dict):
        tool = {}
    driver = tool.get("driver")
    if not isinstance(driver, dict):
        driver = {}
    driver.setdefault("name", "Snyk")
    rules = driver.get("rules")
    if not isinstance(rules, list):
        driver["rules"] = []

    tool["driver"] = driver
    first["tool"] = tool

    results = first.get("results")
    if not isinstance(results, list):
        first["results"] = []

    runs[0] = first
    doc["runs"] = runs
    return first


def dedupe_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rid = str(rule.get("id", "")).strip()
        if not rid:
            continue
        if rid not in deduped:
            deduped[rid] = rule
    return list(deduped.values())


def process_sarif() -> dict[str, Any]:
    doc = ensure_sarif_file()
    doc["version"] = str(doc.get("version") or "2.1.0")

    runs = doc.get("runs")
    if not isinstance(runs, list):
        runs = []

    if len(runs) > 1:
        merged_results: list[dict[str, Any]] = []
        merged_rules: list[dict[str, Any]] = []

        for run in runs:
            if not isinstance(run, dict):
                continue
            results = run.get("results")
            if isinstance(results, list):
                for result in results:
                    if isinstance(result, dict):
                        merged_results.append(result)

            tool = run.get("tool")
            if isinstance(tool, dict):
                driver = tool.get("driver")
                if isinstance(driver, dict):
                    rules = driver.get("rules")
                    if isinstance(rules, list):
                        for rule in rules:
                            if isinstance(rule, dict):
                                merged_rules.append(rule)

        first = runs[0] if isinstance(runs[0], dict) else {}
        tool = first.get("tool") if isinstance(first.get("tool"), dict) else {}
        driver = tool.get("driver") if isinstance(tool.get("driver"), dict) else {}

        first["results"] = merged_results
        driver["rules"] = dedupe_rules(merged_rules + list(driver.get("rules") or []))
        driver.setdefault("name", "Snyk")
        tool["driver"] = driver
        first["tool"] = tool

        doc["runs"] = [first]

    ensure_primary_run(doc)
    write_sarif(doc)
    return doc


def normalized_severity(result: dict[str, Any]) -> str:
    props = result.get("properties") if isinstance(result.get("properties"), dict) else {}

    tags = props.get("tags")
    if isinstance(tags, list):
        for tag in tags:
            if not isinstance(tag, str):
                continue
            if tag.startswith("severity:"):
                sev = tag.split(":", 1)[1].strip().lower()
                return map_level_to_severity(sev)

    sev = props.get("severity")
    if isinstance(sev, str) and sev.strip():
        return map_level_to_severity(sev.strip().lower())

    level = result.get("level")
    if isinstance(level, str) and level.strip():
        return map_level_to_severity(level.strip().lower())

    return "unknown"


def map_level_to_severity(value: str) -> str:
    if value == "error":
        return "high"
    if value == "warning":
        return "medium"
    if value in {"note", "none"}:
        return "low"
    if value == "moderate":
        return "medium"
    if value in {"critical", "high", "medium", "low"}:
        return value
    return "unknown"


def result_component(result: dict[str, Any]) -> str:
    locations = result.get("locations")
    if not isinstance(locations, list) or len(locations) == 0:
        return "unknown"

    loc0 = locations[0]
    if not isinstance(loc0, dict):
        return "unknown"

    logical_locations = loc0.get("logicalLocations")
    if isinstance(logical_locations, list) and len(logical_locations) > 0:
        ll0 = logical_locations[0]
        if isinstance(ll0, dict):
            fqn = ll0.get("fullyQualifiedName")
            if isinstance(fqn, str) and fqn.strip():
                return fqn

    physical = loc0.get("physicalLocation")
    if isinstance(physical, dict):
        artifact = physical.get("artifactLocation")
        if isinstance(artifact, dict):
            uri = artifact.get("uri")
            if isinstance(uri, str) and uri.strip():
                return uri

    return "unknown"


def build_rule_map(runs0: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    tool = runs0.get("tool")
    if not isinstance(tool, dict):
        return out
    driver = tool.get("driver")
    if not isinstance(driver, dict):
        return out
    rules = driver.get("rules")
    if not isinstance(rules, list):
        return out

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rid = str(rule.get("id", "")).strip()
        if rid:
            out[rid] = rule
    return out


def extract_cve(text: str) -> str:
    if not text:
        return "n/a"
    matches = re.findall(r"CVE-\d{4}-\d+", text, flags=re.IGNORECASE)
    if not matches:
        return "n/a"
    unique = []
    seen = set()
    for m in matches:
        up = m.upper()
        if up not in seen:
            seen.add(up)
            unique.append(up)
    return ", ".join(unique)


def rank_severity(sev: str) -> int:
    if sev == "critical":
        return 0
    if sev == "high":
        return 1
    if sev == "medium":
        return 2
    if sev == "low":
        return 3
    return 4


def prepare_summary(doc: dict[str, Any]) -> None:
    run0 = ensure_primary_run(doc)

    results = run0.get("results")
    if not isinstance(results, list):
        results = []

    critical = 0
    high = 0
    medium = 0
    low = 0

    findings: list[dict[str, str]] = []
    rule_map = build_rule_map(run0)

    for item in results:
        if not isinstance(item, dict):
            continue

        rule_id = str(item.get("ruleId", "issue"))
        sev = normalized_severity(item)
        if sev == "critical":
            critical += 1
        elif sev == "high":
            high += 1
        elif sev == "medium":
            medium += 1
        elif sev == "low":
            low += 1

        if sev in {"critical", "high"}:
            component = result_component(item)
            cve = "n/a"
            rule = rule_map.get(rule_id, {})
            if isinstance(rule, dict):
                full_desc = rule.get("fullDescription")
                if isinstance(full_desc, dict):
                    cve = extract_cve(str(full_desc.get("text", "")))
                if cve == "n/a":
                    short_desc = rule.get("shortDescription")
                    if isinstance(short_desc, dict):
                        cve = extract_cve(str(short_desc.get("text", "")))

            if cve == "n/a":
                message = item.get("message")
                if isinstance(message, dict):
                    cve = extract_cve(str(message.get("text", "")))

            findings.append(
                {
                    "rule": rule_id,
                    "severity": sev,
                    "component": component,
                    "cve": cve,
                }
            )

    total = len(results)
    findings.sort(key=lambda x: rank_severity(x["severity"]))

    top_findings = "\n".join(
        f"- {f['rule']} [{f['severity']}] ({f['component']}) CVE: {f['cve']} Disclosure: n/a"
        for f in findings
    )

    if total > 0:
        summary = (
            f"Total: {total} (Critical: {critical}, High: {high}, Medium: {medium}, Low: {low})\n"
            "Source: SARIF"
        )
        if top_findings:
            summary += f"\nFindings:\n{top_findings}"
        if len(summary) > 3000:
            summary = summary[:2970] + "\n...[truncated due Slack message length limit]"
    else:
        summary = "No vulnerabilities found"
        top_findings = ""

    summary = json.dumps(f"*Summary*\n```\n{summary.replace(chr(13), '')}\n```")

    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as f:
            f.write(f"results_count={total}\n")
            f.write(f"critical_count={critical}\n")
            f.write(f"high_count={high}\n")
            f.write(f"medium_count={medium}\n")
            f.write(f"low_count={low}\n")
            f.write("top_findings<<EOF\n")
            f.write(f"{top_findings}\n")
            f.write("EOF\n")
            f.write(f"summary={summary}\n")


def main() -> int:
    doc = process_sarif()
    prepare_summary(doc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
