#!/usr/bin/env python3
import json
import sys
from collections import Counter
from pathlib import Path


def summarize(path: Path) -> int:
    with path.open(encoding="utf-8") as f:
        sarif = json.load(f)

    run = sarif["runs"][0]
    results = run.get("results", [])
    rules = {rule["id"]: rule for rule in run["tool"]["driver"].get("rules", [])}

    print(f"\n{path}")
    print(f"  tool: {run['tool']['driver'].get('name')} {run['tool']['driver'].get('semanticVersion')}")
    print(f"  results: {len(results)}")

    for rule_id, count in Counter(result.get("ruleId") for result in results).most_common():
        rule = rules.get(rule_id, {})
        name = rule.get("shortDescription", {}).get("text", "")
        print(f"  {count:4}  {rule_id}  {name}")

    for index, result in enumerate(results, 1):
        loc = result.get("locations", [{}])[0].get("physicalLocation", {})
        artifact = loc.get("artifactLocation", {}).get("uri", "")
        region = loc.get("region", {})
        line = region.get("startLine", "")
        col = region.get("startColumn", "")
        message = result.get("message", {}).get("text", "").replace("\n", " ")
        print(f"    {index}. {result.get('ruleId')} {artifact}:{line}:{col}")
        print(f"       {message}")

    return len(results)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: summarize_sarif.py <file.sarif> [file.sarif ...]", file=sys.stderr)
        return 2

    for arg in sys.argv[1:]:
        summarize(Path(arg))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
