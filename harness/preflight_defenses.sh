#!/usr/bin/env bash
# GPU-free check of the DEFENSE wiring, on a Zaratan login node (~2 min): runs AgentDojo's real benchmark
# CLI from the image on Banking user_task_0, once per defense, against harness/fake_openai_server.py.
#   harness/preflight_defenses.sh
# The PI detector cases need the ProtectAI weights in the shared HF cache (harness/README.md); they run
# the detector on CPU exactly as run_baseline.sh does: on the clean bill (must pass), under a blatant
# 'ignore your previous instructions' injection (must be redacted), and under the stock attack (reported).
set -uo pipefail
cd "$(dirname "$0")/.."
SIF=${SIF:-/scratch/zt1/project/cmsc848n/shared/proj05_agentdojo/images/agentdojo-7995ab7c1c2b.sif}
command -v apptainer >/dev/null || { type module >/dev/null 2>&1 || source /usr/share/Modules/init/bash; module load apptainer; }
SHARED=${SHARED:-/scratch/zt1/project/cmsc848n/shared/proj05_agentdojo}
T=$(mktemp -d "/tmp/$USER-defense-preflight.XXXX")
fails=0
case_env=() # extra environment for the benchmark process (the PI detector cases)
run_case() { # run_case <case> <defense> <served names> [extra benchmark args...]
  local case=$1 def=$2 names=$3 port=$((20000 + RANDOM % 20000)) srv rc
  shift 3
  python3 harness/fake_openai_server.py serve "$port" "$names" "$T/$case.jsonl" &
  srv=$!
  for _ in $(seq 50); do curl -sf "http://127.0.0.1:$port/health" >/dev/null && break; sleep 0.2; done
  LOCAL_LLM_PORT=$port apptainer exec --bind /scratch "$SIF" env ${case_env[@]+"${case_env[@]}"} \
    /opt/agentdojo/bin/python -m agentdojo.scripts.benchmark \
    --model VLLM_PARSED --benchmark-version v1.2.2 --logdir "$T/$case/runs" ${def:+--defense "$def"} \
    --suite banking --user-task user_task_0 "$@" >"$T/$case.log" 2>&1
  rc=$?
  kill "$srv" 2>/dev/null; wait "$srv" 2>/dev/null
  echo "== $case (defense='${def:-none}', served: $names, exit $rc)"
  python3 harness/fake_openai_server.py check "$case" "$T/$case.jsonl" "$T/$case.log" "$T/$case" || fails=$((fails + 1))
}
run_case none "" qwen3.8-27b
run_case tool_filter_unfixed tool_filter qwen3.8-27b
run_case tool_filter tool_filter qwen3.8-27b,vllm_parsed
run_case spotlighting_with_delimiting spotlighting_with_delimiting qwen3.8-27b
run_case repeat_user_prompt repeat_user_prompt qwen3.8-27b
# PI detector: same environment as run_baseline.sh (borrowed torch + transformers, CPU, offline weights)
case_env=(PYTHONPATH="$PWD/harness" HF_HOME="$SHARED/hf" HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
  WSA_EXTRA_SITE=/usr/local/lib/python3.12/dist-packages CUDA_VISIBLE_DEVICES= OMP_NUM_THREADS=2)
run_case pi_detector_clean transformers_pi_detector qwen3.8-27b --module-to-load wsa_middleware
run_case pi_detector_attack transformers_pi_detector qwen3.8-27b --module-to-load wsa_middleware \
  --attack ignore_previous --injection-task injection_task_0
run_case pi_detector_stock transformers_pi_detector qwen3.8-27b --module-to-load wsa_middleware \
  --attack important_instructions --injection-task injection_task_0
case_env=()
echo
if [ "$fails" -eq 0 ]; then echo "ALL CHECKS PASSED (details in $T)"; else echo "$fails CHECK(S) FAILED; logs in $T"; fi
