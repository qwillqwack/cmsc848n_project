"""Total AgentDojo's per-task result files into utility and attack success per suite.

Usage: python3 summarize.py <run dir>

AgentDojo writes one JSON per task under <run dir>/runs/<benign|attack>/; with several
processes per suite (run_baseline.sh's shards) its own printed averages only cover each
process's share, so this reads the files instead. Standard library only, and Python 3.6
compatible so it also runs on Zaratan's login nodes.
"""
import json
import sys
from collections import defaultdict
from pathlib import Path


def pct(flags):
    if not flags:
        return "-"
    return "{:5.1f}% ({}/{})".format(100.0 * sum(flags) / len(flags), sum(flags), len(flags))


def main():
    run_dir = Path(sys.argv[1])
    benign = defaultdict(list)          # suite -> utility flags
    inj_as_user = defaultdict(list)     # suite -> utility flags
    attacked = defaultdict(lambda: {"utility": [], "hijacked": []})  # (suite, attack) -> flags
    errors = defaultdict(int)
    for path in sorted((run_dir / "runs").glob("**/*.json")):
        result = json.loads(path.read_text())
        if "suite_name" not in result:
            continue
        suite = result["suite_name"]
        if result.get("error"):
            errors[suite] += 1
        utility = bool(result.get("utility"))
        # AgentDojo also runs each injection task as a plain user task (no attack) to check the
        # agent can do it at all; those are not user tasks, so keep them out of benign utility.
        if str(result.get("user_task_id", "")).startswith("injection_task"):
            inj_as_user[suite].append(utility)
        elif result.get("attack_type") is None:
            benign[suite].append(utility)
        else:
            a = attacked[(suite, result["attack_type"])]
            a["utility"].append(utility)
            # AgentDojo calls this "security": True means the injection task was carried out
            a["hijacked"].append(bool(result.get("security")))

    suites = sorted(set(benign) | set(inj_as_user) | set(s for s, _ in attacked))
    if not suites:
        print("no AgentDojo results under {}/runs".format(run_dir))
        return
    row = "{:<10} {:<24} {:<18} {:<22} {:<22} {:<20} {}"
    print(row.format("suite", "attack", "benign utility", "utility under attack", "attack success (ASR)",
                     "inj. tasks as user", "errors"))
    for name in suites:
        attacks = sorted(a for s, a in attacked if s == name) or ["-"]
        for i, att in enumerate(attacks):
            a = attacked.get((name, att), {"utility": [], "hijacked": []})
            print(row.format(name, att, pct(benign[name]) if i == 0 else "",
                             pct(a["utility"]), pct(a["hijacked"]),
                             pct(inj_as_user[name]) if i == 0 else "", errors[name] if i == 0 else ""))
    print("ASR is AgentDojo's 'security' (lower is better); benign utility excludes injection tasks run as user tasks")


if __name__ == "__main__":
    main()
