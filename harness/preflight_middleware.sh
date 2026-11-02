#!/usr/bin/env bash
# GPU-free check of the middleware (harness/wsa_middleware.py) on a Zaratan login node (~1 min): runs
# AgentDojo's real benchmark CLI from the image on Banking user_task_0 against harness/fake_openai_server.py
# in "pay" mode (the fake agent reads the bill, then pays the attacker's IBAN), with different checkers.
#   harness/preflight_middleware.sh
set -uo pipefail
cd "$(dirname "$0")/.."
SIF=${SIF:-/scratch/zt1/project/cmsc848n/shared/proj05_agentdojo/images/agentdojo-7995ab7c1c2b.sif}
command -v apptainer >/dev/null || { type module >/dev/null 2>&1 || source /usr/share/Modules/init/bash; module load apptainer; }
T=$(mktemp -d "/tmp/$USER-middleware-preflight.XXXX")
AD_PATH=$PWD/harness
if [ -d judge ]; then AD_PATH="$AD_PATH:$PWD/judge"; fi
fails=0
run_case() { # run_case <case> <WSA_CHECKER> <WSA_BLOCK_MESSAGE> <defense or "">
  local case=$1 chk=$2 msg=$3 def=$4 port=$((20000 + RANDOM % 20000)) srv rc
  local names=qwen3.8-27b
  if [ "$def" = tool_filter ]; then names=qwen3.8-27b,vllm_parsed; fi
  python3 harness/fake_openai_server.py serve "$port" "$names" "$T/$case.jsonl" pay &
  srv=$!
  for _ in $(seq 50); do curl -sf "http://127.0.0.1:$port/health" >/dev/null && break; sleep 0.2; done
  WSA_CHECKER=$chk WSA_BLOCK_MESSAGE=$msg PYTHONPATH=$AD_PATH LOCAL_LLM_PORT=$port \
    apptainer exec --bind /scratch "$SIF" /opt/agentdojo/bin/python -m agentdojo.scripts.benchmark \
    --model VLLM_PARSED --benchmark-version v1.2.2 --logdir "$T/$case/runs" ${def:+--defense "$def"} \
    --module-to-load wsa_middleware --suite banking --user-task user_task_0 >"$T/$case.log" 2>&1
  rc=$?
  kill "$srv" 2>/dev/null; wait "$srv" 2>/dev/null
  echo "== $case (checker='${chk:-none}', message=$msg, defense='${def:-none}', exit $rc)"
  python3 harness/check_middleware_preflight.py "$case" "$T/$case" "$T/$case.log" || fails=$((fails + 1))
}
run_case cost_only "" generic ""
run_case block_generic wsa_middleware:block_all generic ""
run_case block_detailed wsa_middleware:block_all detailed ""
run_case user_rule wsa_middleware:recipient_from_user generic ""
run_case tool_filter_checked wsa_middleware:block_all generic tool_filter
if [ -d judge ]; then run_case ryan_rule score_rules:banking_rule_decision generic ""; fi
echo
if [ "$fails" -eq 0 ]; then echo "ALL CHECKS PASSED (details in $T)"; else echo "$fails CHECK(S) FAILED; logs in $T"; fi
