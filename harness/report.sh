#!/usr/bin/env bash
# Workstream A: one report for one or more AgentDojo run folders.
#   harness/report.sh                 # the 3 newest run folders (N=5 harness/report.sh for 5)
#   harness/report.sh <run dir> ...   # specific folders
# For each folder: settings, Slurm state + time, utility/ASR table, per-run analysis, problem runs.
# Everything is also saved to report-<date-time>.txt in the project folder.
set -uo pipefail
cd "$(dirname "$0")/.."
RUNS=${RUNS:-/scratch/zt1/project/cmsc848n/shared/proj05_agentdojo/runs}
if [ $# -eq 0 ]; then mapfile -t dirs < <(ls -td "$RUNS"/2*/ | head -"${N:-3}"); else dirs=("$@"); fi
out=report-$(date +%Y%m%d-%H%M).txt
for d in "${dirs[@]}"; do
  d=${d%/}
  echo "################################################################################"
  echo "## $(basename "$d")"
  if [ -f "$d/config.env" ]; then
    grep -E '^(MODE|THINKING|DEFENSE|SUITES|ATTACKS|ATTACK_USER_TASKS|SLURM_JOB_ID)=' "$d/config.env" | sort -u | sed 's/^/   /'
    job=$(sed -n 's/^SLURM_JOB_ID=//p' "$d/config.env" | tail -1)
    if [ -n "$job" ] && command -v sacct >/dev/null; then
      sacct -j "$job" -X -n -o JobID,State,Elapsed | sed 's/^/   slurm: /'
    fi
  fi
  echo; python3 cluster/docker/summarize.py "$d"
  echo; python3 harness/analyze_runs.py "$d"
  echo; python3 harness/show_run.py "$d"
  echo
done 2>&1 | tee "$out"
echo "saved: $PWD/$out"
