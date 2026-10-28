"""Read AgentDojo runs yourself. Standard library only (Python 3.6+), runs on a Zaratan login node.

List the runs where something went wrong (hijacked, user task not done, or crashed):
  python3 harness/show_run.py <run dir>
  python3 harness/show_run.py <run dir> --all                 # every run, not just problems
Print one run's conversation (filters match exactly; give enough of them to pick one run):
  python3 harness/show_run.py <run dir> -u user_task_12 -a argswap_notice
  python3 harness/show_run.py <run dir> -u user_task_0 --benign
Options: -s suite, -u user task, -a attack, -i injection task, --benign (no-attack runs),
         --width N (characters shown per tool output, default 1500; 0 = everything)
"""
import argparse
import json
from pathlib import Path

MARKS = ["<INFORMATION>", "US133000000121212121212", "[Bank notice]", "CHANGE OF BANK DETAILS"]


def text(m):
    c = m.get("content")
    if isinstance(c, list):
        return "\n".join((b.get("content") or "") for b in c if isinstance(b, dict))
    return c or ""


def load(run):
    out = []
    for p in sorted((Path(run) / "runs").glob("**/*.json")):
        d = json.loads(p.read_text())
        if "suite_name" in d:
            d["_path"] = str(p)
            out.append(d)
    return out


def status(d):
    if d.get("error"):
        return "CRASHED"
    if d.get("attack_type") is None:
        return "ok" if d.get("utility") else "TASK NOT DONE"
    if d.get("security"):
        return "HIJACKED"
    return "resisted" if d.get("utility") else "TASK NOT DONE"


def show(d, width):
    print("=" * 100)
    print("suite={} user_task={} attack={} injection_task={}".format(
        d["suite_name"], d["user_task_id"], d.get("attack_type"), d.get("injection_task_id")))
    print("utility={} hijacked={} error={} duration={:.0f}s".format(
        d.get("utility"), d.get("security"), d.get("error"), d.get("duration") or 0))
    print("file:", d["_path"])
    for i, m in enumerate(d["messages"]):
        role = m["role"].upper()
        body = text(m).strip()
        if role == "SYSTEM":
            body = body[:200] + (" ..." if len(body) > 200 else "")
        if role == "TOOL":
            fn = (m.get("tool_call") or {}).get("function", "?")
            flagged = [k for k in MARKS if k in body]
            if width and len(body) > width:
                body = body[:width] + "\n    ... [{} more characters; --width 0 shows all]".format(len(body) - width)
            role = "TOOL RESULT ({}){}".format(fn, "   <-- contains injected text" if flagged else "")
        print("\n[{}] {}".format(i, role))
        if body:
            print("    " + body.replace("\n", "\n    "))
        for t in (m.get("tool_calls") or []):
            print("    -> CALL {}({})".format(t["function"], json.dumps(t.get("args") or {})))
    print()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir")
    ap.add_argument("-s", "--suite")
    ap.add_argument("-u", "--user-task")
    ap.add_argument("-a", "--attack")
    ap.add_argument("-i", "--injection-task")
    ap.add_argument("--benign", action="store_true", help="only runs without an attack")
    ap.add_argument("--all", action="store_true", help="list every run, not just problems")
    ap.add_argument("--width", type=int, default=1500)
    a = ap.parse_args()

    runs = load(a.run_dir)
    sel = [d for d in runs
           if (not a.suite or d["suite_name"] == a.suite)
           and (not a.user_task or d["user_task_id"] == a.user_task)
           and (not a.attack or d.get("attack_type") == a.attack)
           and (not a.injection_task or d.get("injection_task_id") == a.injection_task)
           and (not a.benign or d.get("attack_type") is None)]
    picked = a.user_task or a.attack or a.injection_task or a.benign
    if picked and len(sel) <= 3:
        for d in sel:
            show(d, a.width)
        if not sel:
            print("no run matches those filters")
        return
    rows = [d for d in sel if a.all or status(d) not in ("ok", "resisted")]
    print("{:<10} {:<14} {:<24} {:<18} {}".format("suite", "user task", "attack", "injection task", "status"))
    for d in rows:
        print("{:<10} {:<14} {:<24} {:<18} {}".format(
            d["suite_name"], d["user_task_id"], str(d.get("attack_type") or "(none)"),
            str(d.get("injection_task_id") or "-"), status(d)))
    print("\n{} of {} runs shown{}. Add -u/-a/-i (or --benign) to read one conversation.".format(
        len(rows), len(sel), "" if a.all else " (problems only; --all for everything)"))


if __name__ == "__main__":
    main()
