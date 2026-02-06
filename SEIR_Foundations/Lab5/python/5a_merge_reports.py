#!/usr/bin/env python3
import argparse
import json
import os
import re
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import urllib.request

# Reason why Darth Malgus would be pleased with this script.
# Malgus hates scattered intelligence. This script consolidates the battlefield reports into one briefing.
# Reason why this script is relevant to your career.
# Real security work is turning tool noise into analyst-ready evidence without inventing facts.
# How you would talk about this script at an interview.
# "I built an offline LLM-assisted report merger that preserves tool-reported severity and produces an audit-friendly packet."

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNSPECIFIED"]

def safe_load_json(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

def normalize_sev(sev: Optional[str]) -> str:
    if not sev:
        return "UNSPECIFIED"
    s = str(sev).strip().upper()
    # common variants
    mapping = {
        "CRIT": "CRITICAL",
        "SEVERE": "HIGH",
        "MODERATE": "MEDIUM",
        "INFORMATIONAL": "INFO",
    }
    return mapping.get(s, s) if mapping.get(s, s) in SEV_ORDER else "UNSPECIFIED"

def extract_findings_generic(obj: Any, source: str) -> List[Dict[str, Any]]:
    """
    Generic extraction fallback:
    - searches for dict-like items with keys resembling: severity, title/name, description/message, id, resource/path
    - creates normalized finding records
    """
    findings = []

    def walk(x):
        if isinstance(x, dict):
            yield x
            for v in x.values():
                yield from walk(v)
        elif isinstance(x, list):
            for i in x:
                yield from walk(i)

    for d in walk(obj):
        keys = {k.lower() for k in d.keys()}
        if any(k in keys for k in ["severity", "level", "risk", "priority"]) and any(k in keys for k in ["title", "name", "check", "rule", "id"]):
            title = d.get("title") or d.get("name") or d.get("check") or d.get("rule") or d.get("id")
            sev = d.get("severity") or d.get("level") or d.get("risk") or d.get("priority")
            desc = d.get("description") or d.get("message") or d.get("details") or ""
            resource = d.get("resource") or d.get("file") or d.get("path") or d.get("target") or ""
            cve = d.get("cve") or d.get("cves") or ""
            findings.append({
                "source": source,
                "title": str(title)[:200],
                "severity": normalize_sev(sev),
                "description": str(desc)[:2000],
                "resource": str(resource)[:500],
                "cve": cve,
            })
    return findings

def dedupe(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for f in findings:
        key = (f.get("title","").lower(), f.get("resource","").lower(), f.get("severity",""))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out

def call_local_llm_ollama(prompt: str, model: str, url: str) -> str:
    """
    Ollama generate API:
    POST /api/generate {"model":"llama3.1","prompt":"...", "stream":false}
    """
    payload = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type":"application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("response","").strip()

def build_llm_prompt(findings: List[Dict[str, Any]]) -> str:
    # Keep context bounded: pass only essential fields.
    # You can also chunk if you have tons of findings.
    items = []
    for f in findings[:400]:  # cap for classroom safety
        items.append({
            "source": f["source"],
            "severity": f["severity"],
            "title": f["title"],
            "resource": f.get("resource",""),
            "description": f.get("description",""),
        })

    rules = """
You are a security report MERGER. You must follow these rules:
- You may summarize and group findings.
- You MUST NOT invent severities, CVEs, or risk scores.
- Preserve each tool's severity exactly as provided in the input.
- If severity is missing, use "UNSPECIFIED".
- Do not include exploit steps or payloads.
- Output in Markdown using the requested sections exactly.
"""

    request = """
Create a consolidated report with:
1) Executive Summary (no new severities)
2) Findings by Source Tool
3) Findings by Severity (as-reported)
4) Findings by Category (OWASP / IaC / Cloud / Dependencies)
5) Suspected Duplicates (only if obvious)
6) Analyst Next Actions checklist
7) Appendix: Evidence counts per tool

Use short bullets. Be precise. If a field is missing, say "Unknown".
"""

    return rules.strip() + "\n\n" + request.strip() + "\n\nINPUT_FINDINGS_JSON:\n" + json.dumps(items, indent=2)

def render_fallback_report(findings: List[Dict[str, Any]]) -> str:
    by_source: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        by_source.setdefault(f["source"], []).append(f)

    lines = []
    lines.append("# Consolidated Security Report (Fallback)\n")
    lines.append("## Executive Summary\n")
    lines.append(f"- Total findings: {len(findings)}")
    lines.append("- Severity counts (as-reported):")
    for sev in SEV_ORDER:
        lines.append(f"  - {sev}: {sum(1 for x in findings if x['severity']==sev)}")

    lines.append("\n## Findings by Source Tool\n")
    for src, items in sorted(by_source.items()):
        lines.append(f"### {src} ({len(items)})")
        for f in items[:30]:
            lines.append(f"- [{f['severity']}] {f['title']} — {f.get('resource','')}".strip())

    lines.append("\n## Findings by Severity (as-reported)\n")
    for sev in SEV_ORDER:
        items = [x for x in findings if x["severity"] == sev]
        if not items:
            continue
        lines.append(f"### {sev} ({len(items)})")
        for f in items[:50]:
            lines.append(f"- {f['title']} ({f.get('source')})")

    lines.append("\n## Analyst Next Actions\n")
    lines.append("- [ ] Validate Critical/High findings directly in the environment")
    lines.append("- [ ] Confirm scope and false positives")
    lines.append("- [ ] Create remediation tickets with owners + deadlines")
    lines.append("- [ ] Add/adjust detections for repeated patterns\n")
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-dir", default="inputs")
    ap.add_argument("--output-dir", default="outputs")
    ap.add_argument("--llm", choices=["none","ollama"], default="ollama")
    ap.add_argument("--ollama-url", default="http://localhost:11434/api/generate")
    ap.add_argument("--model", default="llama3.1")
    args = ap.parse_args()

    in_dir = Path(args.input_dir)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_findings: List[Dict[str, Any]] = []

    for p in sorted(in_dir.glob("*")):
        if p.suffix.lower() != ".json":
            continue
        data = safe_load_json(p)
        if data is None:
            continue
        all_findings.extend(extract_findings_generic(data, source=p.stem))

    all_findings = dedupe(all_findings)

    (out_dir / "extracted_findings.json").write_text(json.dumps(all_findings, indent=2), encoding="utf-8")

    if args.llm == "ollama":
        prompt = build_llm_prompt(all_findings)
        try:
            md = call_local_llm_ollama(prompt, model=args.model, url=args.ollama_url)
        except Exception as e:
            md = f"# Consolidated Security Report\n\nLLM call failed: {e}\n\n" + render_fallback_report(all_findings)
    else:
        md = render_fallback_report(all_findings)

    (out_dir / "consolidated_security_report.md").write_text(md, encoding="utf-8")
    print(f"Wrote: {out_dir/'consolidated_security_report.md'}")
    print(f"Wrote: {out_dir/'extracted_findings.json'}")

if __name__ == "__main__":
    main()
