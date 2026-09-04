#!/usr/bin/env python3
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

SARIF_PATH = "snyk-results.sarif"
SNYK_JSON_PATH = "snyk-results.json"


def ensure_sarif_file() -> None:
  if not os.path.exists(SARIF_PATH) or os.path.getsize(SARIF_PATH) == 0:
    doc = {
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
    with open(SARIF_PATH, "w", encoding="utf-8") as handle:
      json.dump(doc, handle, separators=(",", ":"))


def load_json(path: str, default: Any) -> Any:
  try:
    with open(path, "r", encoding="utf-8") as handle:
      return json.load(handle)
  except (OSError, json.JSONDecodeError):
    return default


def write_json(path: str, payload: Any) -> None:
  tmp = f"{path}.tmp"
  with open(tmp, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
  os.replace(tmp, path)


def get_run(doc: Dict[str, Any]) -> Dict[str, Any]:
  runs = doc.get("runs")
  if not isinstance(runs, list):
    runs = []
  if not runs:
    runs = [{"tool": {"driver": {"name": "Snyk", "rules": []}}, "results": []}]
    doc["runs"] = runs

  run = runs[0] if isinstance(runs[0], dict) else {}
  if not isinstance(run, dict):
    run = {}
  runs[0] = run

  tool = run.get("tool") if isinstance(run.get("tool"), dict) else {}
  driver = tool.get("driver") if isinstance(tool.get("driver"), dict) else {}
  if not driver.get("name"):
    driver["name"] = "Snyk"
  if not isinstance(driver.get("rules"), list):
    driver["rules"] = []
  tool["driver"] = driver
  run["tool"] = tool

  if not isinstance(run.get("results"), list):
    run["results"] = []

  return run


def unique_preserve(items: List[Any]) -> List[Any]:
  out: List[Any] = []
  seen = set()
  for item in items:
    key = json.dumps(item, sort_keys=True, ensure_ascii=False)
    if key in seen:
      continue
    seen.add(key)
    out.append(item)
  return out


def unique_strings(items: List[str]) -> List[str]:
  out: List[str] = []
  seen = set()
  for item in items:
    if item in seen:
      continue
    seen.add(item)
    out.append(item)
  return out


def docs_roots(docs: Any) -> List[Dict[str, Any]]:
  if isinstance(docs, list):
    return [item for item in docs if isinstance(item, dict)]
  if isinstance(docs, dict):
    return [docs]
  return []


def id_list(vuln: Any, key: str) -> List[str]:
  if not isinstance(vuln, dict):
    return []
  identifiers = vuln.get("identifiers")
  if not isinstance(identifiers, dict):
    return []
  values = identifiers.get(key)
  if not isinstance(values, list):
    return []
  return [str(v) for v in values]


def all_vulns(docs: Any) -> List[Dict[str, Any]]:
  out: List[Dict[str, Any]] = []
  for root in docs_roots(docs):
    root_target = str(root.get("displayTargetFile") or root.get("targetFile") or "")

    root_vulns = root.get("vulnerabilities")
    if isinstance(root_vulns, list):
      for vuln in root_vulns:
        if isinstance(vuln, dict):
          merged = dict(vuln)
          merged["__targetFile"] = str(
            root.get("displayTargetFile")
            or root.get("targetFile")
            or vuln.get("displayTargetFile")
            or vuln.get("targetFile")
            or ""
          )
          out.append(merged)

    apps = root.get("applications")
    if isinstance(apps, list):
      for app in apps:
        if not isinstance(app, dict):
          continue
        app_vulns = app.get("vulnerabilities")
        if not isinstance(app_vulns, list):
          continue
        for vuln in app_vulns:
          if not isinstance(vuln, dict):
            continue
          merged = dict(vuln)
          merged["__targetFile"] = str(
            app.get("displayTargetFile")
            or app.get("targetFile")
            or root_target
            or vuln.get("displayTargetFile")
            or vuln.get("targetFile")
            or ""
          )
          out.append(merged)
  return out


def package_of(vuln: Dict[str, Any]) -> str:
  name = vuln.get("packageName") or vuln.get("name") or ""
  if name:
    return f"{name}@{vuln.get('version', 'unknown')}"
  return "unknown"


def vuln_sev(vuln: Dict[str, Any]) -> str:
  sev = str(vuln.get("severity", "unknown")).lower()
  return "medium" if sev == "moderate" else sev


def level_of(sev: str) -> str:
  if sev in {"critical", "high"}:
    return "error"
  if sev == "medium":
    return "warning"
  if sev == "low":
    return "note"
  return "warning"


def security_severity_of(vuln: Dict[str, Any]) -> str:
  sev = vuln_sev(vuln)
  if sev == "critical":
    return "9.0"
  if sev == "high":
    return "7.0"
  if sev == "medium":
    return "4.0"
  if sev == "low":
    return "1.0"
  return "0.0"


def csv_trimmed(text: str) -> str:
  parts = [p.strip() for p in str(text or "").split(",")]
  filtered = [p for p in parts if p and p.lower() != "n/a"]
  return ", ".join(unique_strings(filtered))


def cves_of(vuln: Dict[str, Any]) -> str:
  return ", ".join(unique_strings(id_list(vuln, "CVE")))


def cwes_of(vuln: Dict[str, Any]) -> str:
  return ", ".join(unique_strings(id_list(vuln, "CWE"))[:3])


def ghsas_of(vuln: Dict[str, Any]) -> str:
  return ", ".join(unique_strings(id_list(vuln, "GHSA"))[:3])


def disclosure_of(vuln: Dict[str, Any]) -> str:
  value = (
    vuln.get("disclosureTime")
    or vuln.get("publicationTime")
    or vuln.get("creationTime")
    or ""
  )
  return str(value)[:10]


def strip_severity_prefix(text: str) -> str:
  return re.sub(
    r"^(critical|high|medium|low)\s+severity\s*-\s*",
    "",
    str(text or ""),
    flags=re.IGNORECASE,
  )


def with_id_prefix(rule_id: str, text: str) -> str:
  rid = rule_id or "issue"
  clean = strip_severity_prefix(text)
  if clean.startswith(f"{rid} - "):
    return clean
  return f"{rid} - {clean}"


def with_cve_suffix(text: str, cves: str) -> str:
  cve_text = csv_trimmed(cves)
  base = str(text or "")
  if not cve_text:
    return base
  if " | CVE:" in base:
    return base
  return f"{base} | CVE: {cve_text}"


def target_file_of(vuln: Dict[str, Any]) -> str:
  return str(
    vuln.get("__targetFile")
    or vuln.get("displayTargetFile")
    or vuln.get("targetFile")
    or ""
  )


def fingerprint_of(vuln: Dict[str, Any]) -> str:
  target = target_file_of(vuln) or "n/a"
  return f"{vuln.get('id', 'issue')}|{package_of(vuln)}|{target}"


def location_of(vuln: Dict[str, Any]) -> Dict[str, Any]:
  package_name = package_of(vuln)
  target = target_file_of(vuln)
  if target:
    return {
      "physicalLocation": {
        "artifactLocation": {"uri": target},
        "region": {"startLine": 1},
      },
      "logicalLocations": [
        {
          "fullyQualifiedName": package_name,
        }
      ],
    }
  return {
    "logicalLocations": [
      {
        "fullyQualifiedName": package_name,
      }
    ]
  }


def component_of_result(result: Dict[str, Any]) -> str:
  locations = result.get("locations")
  if not isinstance(locations, list) or not locations:
    return "unknown"
  first = locations[0] if isinstance(locations[0], dict) else {}

  logical = first.get("logicalLocations")
  if isinstance(logical, list) and logical and isinstance(logical[0], dict):
    fqn = logical[0].get("fullyQualifiedName")
    if fqn:
      return str(fqn)

  physical = first.get("physicalLocation")
  if isinstance(physical, dict):
    artifact = physical.get("artifactLocation")
    if isinstance(artifact, dict) and artifact.get("uri"):
      return str(artifact.get("uri"))

  return "unknown"


def find_vuln(
  vulns: List[Dict[str, Any]], rule_id: str, component: str
) -> Optional[Dict[str, Any]]:
  for vuln in vulns:
    if str(vuln.get("id", "")) == rule_id and package_of(vuln) == component:
      return vuln
  for vuln in vulns:
    if str(vuln.get("id", "")) == rule_id:
      return vuln
  return None


def ui_tags(vuln: Dict[str, Any]) -> List[str]:
  tags = [f"cve:{v}" for v in id_list(vuln, "CVE")]
  tags.extend(f"cwe:{v}" for v in id_list(vuln, "CWE"))
  tags.extend(f"ghsa:{v}" for v in id_list(vuln, "GHSA"))
  return unique_strings(tags)


def normalize_sarif(doc: Dict[str, Any]) -> Dict[str, Any]:
  doc["version"] = doc.get("version") or "2.1.0"

  runs = doc.get("runs") if isinstance(doc.get("runs"), list) else []
  if len(runs) <= 1:
    if not runs:
      doc["runs"] = [
        {"tool": {"driver": {"name": "Snyk", "rules": []}}, "results": []}
      ]
    return doc

  first = runs[0] if isinstance(runs[0], dict) else {}
  merged_results: List[Any] = []
  for run in runs:
    if not isinstance(run, dict):
      continue
    results = run.get("results")
    if isinstance(results, list):
      merged_results.extend(results)
  first["results"] = merged_results
  doc["runs"] = [first]
  return doc


def get_rule_cves(rule: Dict[str, Any]) -> str:
  props = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
  explicit = props.get("cve")
  if explicit:
    return str(explicit)

  full_desc = (
    rule.get("fullDescription")
    if isinstance(rule.get("fullDescription"), dict)
    else {}
  )
  text = str(full_desc.get("text") or "")
  matches = re.findall(r"CVE-[0-9]{4}-[0-9]+", text)
  return ", ".join(unique_strings(matches))


def process_sarif() -> None:
  ensure_sarif_file()

  sarif = load_json(SARIF_PATH, {})
  if not isinstance(sarif, dict):
    sarif = {}

  sarif = normalize_sarif(sarif)
  run = get_run(sarif)

  snyk_docs = load_json(SNYK_JSON_PATH, {})
  vulns = all_vulns(snyk_docs)

  existing_results = (
    run.get("results") if isinstance(run.get("results"), list) else []
  )
  if existing_results:
    new_results: List[Dict[str, Any]] = []
    for raw_result in existing_results:
      if not isinstance(raw_result, dict):
        continue

      result = dict(raw_result)
      rule_id = str(result.get("ruleId") or "issue")
      component = component_of_result(result)
      vuln = find_vuln(vulns, rule_id, component)

      if vuln is None:
        new_results.append(result)
        continue

      message = (
        result.get("message") if isinstance(result.get("message"), dict) else {}
      )
      base_message = str(
        message.get("text") or vuln.get("title") or "Snyk vulnerability"
      )
      message["text"] = with_id_prefix(rule_id, base_message)

      if " | Package:" not in message["text"]:
        extra = (
          f" | Package: {package_of(vuln)}"
          f" | CVE: {cves_of(vuln) or 'n/a'}"
          f" | CWE: {cwes_of(vuln) or 'n/a'}"
          f" | GHSA: {ghsas_of(vuln) or 'n/a'}"
          f" | Disclosure: {disclosure_of(vuln) or 'n/a'}"
          f" | Ref: https://security.snyk.io/vuln/{rule_id}"
        )
        message["text"] = f"{message['text']}{extra}"
      result["message"] = message

      locations = (
        result.get("locations")
        if isinstance(result.get("locations"), list)
        else []
      )
      vuln_target = target_file_of(vuln)
      if not locations:
        result["locations"] = [location_of(vuln)]
      else:
        first = locations[0] if isinstance(locations[0], dict) else {}
        physical = (
          first.get("physicalLocation")
          if isinstance(first.get("physicalLocation"), dict)
          else {}
        )
        artifact = (
          physical.get("artifactLocation")
          if isinstance(physical.get("artifactLocation"), dict)
          else {}
        )
        uri = str(artifact.get("uri") or "")
        if not uri and vuln_target:
          artifact["uri"] = vuln_target
          physical["artifactLocation"] = artifact
          region = (
            physical.get("region")
            if isinstance(physical.get("region"), dict)
            else {}
          )
          region["startLine"] = 1
          physical["region"] = region
          first["physicalLocation"] = physical
          locations[0] = first
          result["locations"] = locations

      properties = (
        result.get("properties")
        if isinstance(result.get("properties"), dict)
        else {}
      )
      existing_tags = (
        properties.get("tags")
        if isinstance(properties.get("tags"), list)
        else []
      )
      merged_tags = [str(tag) for tag in existing_tags]
      merged_tags.append(f"severity:{vuln_sev(vuln)}")
      merged_tags.extend(ui_tags(vuln))
      properties.update(
        {
          "severity": vuln_sev(vuln),
          "tags": unique_strings(merged_tags),
          "security-severity": security_severity_of(vuln),
          "cve": cves_of(vuln) or "n/a",
        }
      )
      result["properties"] = properties

      partial = (
        result.get("partialFingerprints")
        if isinstance(result.get("partialFingerprints"), dict)
        else {}
      )
      partial["primaryLocationLineHash"] = fingerprint_of(vuln)
      result["partialFingerprints"] = partial

      new_results.append(result)
    run["results"] = new_results
  else:
    generated: List[Dict[str, Any]] = []
    for vuln in vulns:
      sev = vuln_sev(vuln)
      generated.append(
        {
          "ruleId": vuln.get("id", "issue"),
          "level": level_of(sev),
          "message": {
            "text": f"{vuln.get('id', 'issue')} - {vuln.get('title') or vuln.get('id') or 'Snyk vulnerability'}"
          },
          "locations": [location_of(vuln)],
          "properties": {
            "severity": sev,
            "tags": unique_strings([f"severity:{sev}"] + ui_tags(vuln)),
            "security-severity": security_severity_of(vuln),
            "cve": cves_of(vuln) or "n/a",
          },
          "partialFingerprints": {
            "primaryLocationLineHash": fingerprint_of(vuln),
          },
        }
      )

    dedup: List[Dict[str, Any]] = []
    seen_keys = set()
    for result in generated:
      locations = (
        result.get("locations")
        if isinstance(result.get("locations"), list) and result.get("locations")
        else []
      )
      first = locations[0] if locations and isinstance(locations[0], dict) else {}
      physical = (
        first.get("physicalLocation")
        if isinstance(first.get("physicalLocation"), dict)
        else {}
      )
      artifact = (
        physical.get("artifactLocation")
        if isinstance(physical.get("artifactLocation"), dict)
        else {}
      )
      logical = (
        first.get("logicalLocations")
        if isinstance(first.get("logicalLocations"), list)
        and first.get("logicalLocations")
        else []
      )
      logical_first = (
        logical[0] if logical and isinstance(logical[0], dict) else {}
      )

      component = (
        artifact.get("uri")
        or logical_first.get("fullyQualifiedName")
        or "unknown"
      )
      key = f"{result.get('ruleId', 'issue')}|{component}"
      if key in seen_keys:
        continue
      seen_keys.add(key)
      dedup.append(result)
    run["results"] = dedup

  enriched_rules: List[Dict[str, Any]] = []
  seen_rule_ids = set()
  for vuln in vulns:
    rid = str(vuln.get("id") or "issue")
    if rid in seen_rule_ids:
      continue
    seen_rule_ids.add(rid)
    cves = cves_of(vuln)
    enriched_rules.append(
      {
        "id": rid,
        "name": rid,
        "shortDescription": {
          "text": with_cve_suffix(
            f"{rid} - {vuln.get('title') or rid or 'Snyk vulnerability'}",
            cves,
          )
        },
        "fullDescription": {
          "text": f"{rid} - {vuln.get('title') or vuln.get('description') or 'Snyk vulnerability'} | CVE: {cves or 'n/a'}"
        },
        "helpUri": f"https://security.snyk.io/vuln/{rid}",
        "properties": {
          "tags": ui_tags(vuln),
          "security-severity": security_severity_of(vuln),
          "cve": cves or "n/a",
        },
      }
    )

  existing_rules = run["tool"]["driver"].get("rules")
  if not isinstance(existing_rules, list):
    existing_rules = []

  combined_rules = enriched_rules + [
    rule for rule in existing_rules if isinstance(rule, dict)
  ]
  dedup_rules: List[Dict[str, Any]] = []
  seen_rules = set()
  for rule in combined_rules:
    rid = str(rule.get("id") or "")
    if rid in seen_rules:
      continue
    seen_rules.add(rid)
    dedup_rules.append(rule)

  for rule in dedup_rules:
    rid = str(rule.get("id") or "issue")
    cves = get_rule_cves(rule)
    short_desc = (
      rule.get("shortDescription")
      if isinstance(rule.get("shortDescription"), dict)
      else {}
    )
    short_text = (
      short_desc.get("text")
      or rule.get("name")
      or rule.get("id")
      or "Snyk vulnerability"
    )
    short_desc["text"] = with_cve_suffix(with_id_prefix(rid, str(short_text)), cves)
    rule["shortDescription"] = short_desc

  run["tool"]["driver"]["rules"] = dedup_rules

  rule_by_id = {str(rule.get("id") or ""): rule for rule in dedup_rules}

  updated_results: List[Dict[str, Any]] = []
  for raw_result in run.get("results", []):
    if not isinstance(raw_result, dict):
      continue
    result = dict(raw_result)

    rid = str(result.get("ruleId") or "issue")
    rule = rule_by_id.get(rid, {})
    rule_short_desc = (
      rule.get("shortDescription")
      if isinstance(rule.get("shortDescription"), dict)
      else {}
    )

    properties = (
      result.get("properties")
      if isinstance(result.get("properties"), dict)
      else {}
    )
    cves = str(
      properties.get("cve")
      or (
        (
          rule.get("properties")
          if isinstance(rule.get("properties"), dict)
          else {}
        ).get("cve")
        if isinstance(rule, dict)
        else ""
      )
      or get_rule_cves(rule if isinstance(rule, dict) else {})
      or ""
    )

    message = (
      result.get("message") if isinstance(result.get("message"), dict) else {}
    )
    msg_text = str(
      message.get("text") or rule_short_desc.get("text") or "Snyk vulnerability"
    )
    message["text"] = with_cve_suffix(with_id_prefix(rid, msg_text), cves)
    result["message"] = message

    clean_cves = csv_trimmed(cves)
    properties["cve"] = clean_cves if clean_cves else "n/a"
    result["properties"] = properties

    updated_results.append(result)

  run["results"] = updated_results

  write_json(SARIF_PATH, sarif)


def severity_from_sarif_result(result: Dict[str, Any]) -> str:
  properties = (
    result.get("properties") if isinstance(result.get("properties"), dict) else {}
  )

  tags = properties.get("tags") if isinstance(properties.get("tags"), list) else []
  tag_severity: Optional[str] = None
  for tag in tags:
    value = str(tag)
    if value.startswith("severity:"):
      tag_severity = value[len("severity:") :]
      break

  sev = str(
    tag_severity or properties.get("severity") or result.get("level") or "unknown"
  ).lower()
  if sev == "error":
    return "high"
  if sev == "warning":
    return "medium"
  if sev in {"note", "none"}:
    return "low"
  return sev


def norm_json_sev(vuln: Dict[str, Any]) -> str:
  sev = (
    vuln.get("severity")
    or vuln.get("effectiveSeverity")
    or (
      vuln.get("issueData", {}) if isinstance(vuln.get("issueData"), dict) else {}
    ).get("severity")
    or vuln.get("severityLevel")
    or (
      vuln.get("metadata", {}) if isinstance(vuln.get("metadata"), dict) else {}
    ).get("severity")
    or "unknown"
  )
  sev = str(sev).lower()
  if sev == "moderate":
    return "medium"
  if sev == "error":
    return "high"
  if sev == "warning":
    return "medium"
  if sev in {"note", "none"}:
    return "low"
  return sev


def severity_rank(sev: str) -> int:
  if sev == "critical":
    return 0
  if sev == "high":
    return 1
  if sev == "medium":
    return 2
  if sev == "low":
    return 3
  return 4


def prepare_summary() -> None:
  ensure_sarif_file()

  summary_source = "SARIF fallback"

  sarif = load_json(SARIF_PATH, {})
  if not isinstance(sarif, dict):
    sarif = {}

  run = get_run(sarif)
  results = run.get("results") if isinstance(run.get("results"), list) else []

  sarif_sevs = [
    severity_from_sarif_result(item) for item in results if isinstance(item, dict)
  ]
  results_count = len(results)
  critical_count = sum(1 for s in sarif_sevs if s == "critical")
  high_count = sum(1 for s in sarif_sevs if s == "high")
  medium_count = sum(1 for s in sarif_sevs if s == "medium")
  low_count = sum(1 for s in sarif_sevs if s == "low")

  snyk_docs = load_json(SNYK_JSON_PATH, None)
  vulns = all_vulns(snyk_docs) if snyk_docs is not None else []

  if os.path.exists(SNYK_JSON_PATH) and vulns:
    summary_records: List[Dict[str, str]] = []
    seen = set()
    for vuln in vulns:
      record = {
        "rule": str(vuln.get("id") or "issue"),
        "severity": norm_json_sev(vuln),
        "component": package_of(vuln),
      }
      key = f"{record['rule']}|{record['severity']}|{record['component']}"
      if key in seen:
        continue
      seen.add(key)
      summary_records.append(record)

    if summary_records:
      results_count = len(summary_records)
      critical_count = sum(
        1 for r in summary_records if r["severity"] == "critical"
      )
      high_count = sum(1 for r in summary_records if r["severity"] == "high")
      medium_count = sum(1 for r in summary_records if r["severity"] == "medium")
      low_count = sum(1 for r in summary_records if r["severity"] == "low")
      summary_source = "Snyk JSON"

  top_findings_lines: List[str] = []

  if os.path.exists(SNYK_JSON_PATH) and vulns:
    records: List[Dict[str, str]] = []
    seen = set()
    for vuln in vulns:
      rec = {
        "rule": str(vuln.get("id") or "issue"),
        "severity": norm_json_sev(vuln),
        "component": package_of(vuln),
        "cve": cves_of(vuln),
        "disclosure": disclosure_of(vuln),
      }
      if rec["severity"] not in {"critical", "high"}:
        continue
      key = "|".join(
        [
          rec["rule"],
          rec["severity"],
          rec["component"],
          rec["cve"],
          rec["disclosure"],
        ]
      )
      if key in seen:
        continue
      seen.add(key)
      records.append(rec)

    records.sort(key=lambda item: severity_rank(item["severity"]))
    for rec in records:
      top_findings_lines.append(
        f"- {rec['rule']} [{rec['severity']}] ({rec['component']}) "
        f"CVE: {rec['cve'] or 'n/a'} Disclosure: {rec['disclosure'] or 'n/a'}"
      )

  if not top_findings_lines:
    records: List[Dict[str, str]] = []
    for raw in results:
      if not isinstance(raw, dict):
        continue
      sev = severity_from_sarif_result(raw)
      if sev not in {"critical", "high"}:
        continue
      component = component_of_result(raw)
      records.append(
        {
          "rule": str(raw.get("ruleId") or "issue"),
          "severity": sev,
          "component": component,
        }
      )

    records.sort(key=lambda item: severity_rank(item["severity"]))
    for rec in records:
      top_findings_lines.append(
        f"- {rec['rule']} [{rec['severity']}] ({rec['component']}) CVE: n/a Disclosure: n/a"
      )

  top_findings = "\n".join(top_findings_lines)

  if results_count > 0:
    slack_summary = (
      f"Total: {results_count} (Critical: {critical_count}, High: {high_count}, "
      f"Medium: {medium_count}, Low: {low_count})"
    )
    slack_summary += f"\nSource: {summary_source}"
    if top_findings:
      slack_summary += f"\nFindings:\n{top_findings}"

    if len(slack_summary) > 3000:
      slack_summary = (
        slack_summary[:2970] + "\n...[truncated due Slack message length limit]"
      )
  else:
    slack_summary = "No vulnerabilities found"
    top_findings = ""

  github_output = os.environ.get("GITHUB_OUTPUT")
  if github_output:
    with open(github_output, "a", encoding="utf-8") as handle:
      handle.write(f"results_count={results_count}\n")
      handle.write(f"critical_count={critical_count}\n")
      handle.write(f"high_count={high_count}\n")
      handle.write(f"medium_count={medium_count}\n")
      handle.write(f"low_count={low_count}\n")
      handle.write("top_findings<<EOF\n")
      handle.write(f"{top_findings}\n")
      handle.write("EOF\n")
      handle.write("summary<<EOF\n")
      handle.write(f"{slack_summary}\n")
      handle.write("EOF\n")


def main() -> None:
  mode = sys.argv[1] if len(sys.argv) > 1 else "process-sarif"
  if mode == "process-sarif":
    process_sarif()
  elif mode == "prepare-summary":
    prepare_summary()
  elif mode == "all":
    process_sarif()
    prepare_summary()
  else:
    print(f"Unknown mode: {mode}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
  main()
