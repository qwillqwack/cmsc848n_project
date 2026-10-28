#!/usr/bin/env bash
# Inside the container: start vLLM on Qwen3.8-27B, wait until it is healthy, run AgentDojo
# against it, then stop the server. make.sh sets the variables below and records them in
# $OUT/config.env.
set -euo pipefail

: "${MODEL:?}" "${MODEL_REVISION:?}" "${OUT:?}" "${MODE:?}"
MAX_MODEL_LEN=${MAX_MODEL_LEN:-32768}
GPU_MEM_UTIL=${GPU_MEM_UTIL:-0.90}
MAX_NUM_SEQS=${MAX_NUM_SEQS:-8}
ENFORCE_EAGER=${ENFORCE_EAGER:-1}
THINKING=${THINKING:-low}
PORT=${PORT:-8000}
BENCHMARK_VERSION=${BENCHMARK_VERSION:-v1.2.2}
SUITES=${SUITES:-banking} # the project's focus; "all" = workspace slack travel banking
SHARDS=${SHARDS:-4}       # parallel AgentDojo processes per suite, sharing one vLLM server
# MODE=attack: custom attacks from harness/ (Workstream A), Banking only
ATTACKS=${ATTACKS:-argswap_notice argswap_policy important_instructions}
INJECTION_TASKS=${INJECTION_TASKS:-injection_task_100}
ATTACK_USER_TASKS=${ATTACK_USER_TASKS:-user_task_0 user_task_2 user_task_3 user_task_4 user_task_5 user_task_6 user_task_9 user_task_11 user_task_12 user_task_15}
MODULES=${MODULES:-wsa_attacks}
# DEFENSE: one of AgentDojo's built-in defenses, or empty for none (Workstream A task 5 / table T2)
DEFENSE=${DEFENSE:-}
case "$DEFENSE" in
  "" | tool_filter | spotlighting_with_delimiting | repeat_user_prompt) ;;
  transformers_pi_detector)
    echo "DEFENSE=transformers_pi_detector needs torch + transformers in /opt/agentdojo and the ProtectAI" >&2
    echo "weights in \$HF_HOME; neither is in image 7995ab7c1c2b yet" >&2
    exit 2 ;;
  *) echo "unknown DEFENSE '$DEFENSE'" >&2; exit 2 ;;
esac
# AgentDojo 0.1.35's tool filter calls the model by the config name ("vllm_parsed"), not by the served
# id, so serve that name too when the tool filter is on (other runs stay exactly as before).
served=(qwen3.8-27b)
if [ "$DEFENSE" = tool_filter ]; then served+=(vllm_parsed); fi
HARNESS="$(cd "$(dirname "$0")/.." && pwd)/harness" # put on AgentDojo's PYTHONPATH only, not vLLM's

case "$THINKING" in
  off) template_kwargs='{"enable_thinking": false}' ;;
  low | medium | xhigh) template_kwargs="{\"reasoning_effort\": \"$THINKING\"}" ;;
  *) echo "THINKING must be off, low, medium or xhigh (got '$THINKING')" >&2; exit 2 ;;
esac
if [ "$SUITES" = all ]; then SUITES="workspace slack travel banking"; fi

eager=()
if [ "$ENFORCE_EAGER" = 1 ]; then eager=(--enforce-eager); fi

mkdir -p "$OUT"

# Flags follow the vLLM recipe for Qwen3.8-27B: the qwen3 reasoning parser keeps <think>
# blocks out of message.content, and qwen3_coder turns the model's tool calls into OpenAI
# tool_calls, which AgentDojo's vllm_parsed mode reads. Text only, so skip the vision tower.
# On a 40 GB card, CUDA graph capture allocates outside --gpu-memory-utilization and can OOM;
# --enforce-eager avoids that.
vllm serve "$MODEL" --revision "$MODEL_REVISION" \
  --served-model-name "${served[@]}" \
  --max-model-len "$MAX_MODEL_LEN" \
  --gpu-memory-utilization "$GPU_MEM_UTIL" \
  --max-num-seqs "$MAX_NUM_SEQS" \
  "${eager[@]}" \
  --language-model-only \
  --reasoning-parser qwen3 \
  --enable-auto-tool-choice --tool-call-parser qwen3_coder \
  --default-chat-template-kwargs "$template_kwargs" \
  --port "$PORT" >"$OUT/vllm.log" 2>&1 &
server=$!
trap 'kill $server 2>/dev/null || true; wait $server 2>/dev/null || true' EXIT

echo "waiting for vLLM (log: $OUT/vllm.log)"
for _ in $(seq 360); do
  curl -sf "http://localhost:$PORT/health" >/dev/null && break
  if ! kill -0 "$server" 2>/dev/null; then
    echo "vLLM exited during startup:" >&2
    tail -40 "$OUT/vllm.log" >&2
    exit 1
  fi
  sleep 5
done
curl -sf "http://localhost:$PORT/health" >/dev/null || { echo "vLLM not healthy after 30 min" >&2; exit 1; }
echo "vLLM is up"

# bench <benign|attack> <log name> <agentdojo args...>. Every process writes its per-task
# result files under $OUT/runs/<benign|attack>; summarize.py totals them.
bench() {
  local kind=$1 log=$2
  shift 2
  PYTHONPATH="$HARNESS" LOCAL_LLM_PORT=$PORT /opt/agentdojo/bin/python -m agentdojo.scripts.benchmark \
    --model VLLM_PARSED --benchmark-version "$BENCHMARK_VERSION" ${DEFENSE:+--defense "$DEFENSE"} \
    --logdir "$OUT/runs/$kind${LOGSUB:+/$LOGSUB}" "$@" >>"$OUT/$log.log" 2>&1
}

user_tasks() { # user_tasks <suite>: the suite's user task ids, one per line
  /opt/agentdojo/bin/python -c 'import sys
from agentdojo.task_suite.load_suites import get_suite
print("\n".join(get_suite(sys.argv[1], sys.argv[2]).user_tasks))' "$BENCHMARK_VERSION" "$1"
}

# AgentDojo runs one task at a time within a suite, which leaves the GPU mostly idle. Deal
# the suite's user tasks round-robin into $SHARDS processes; each does its share without an
# attack (benign utility), then with important_instructions against every injection task.
run_suite() {
  local suite=$1 k i pids=() failed=0
  local -a tasks args
  mapfile -t tasks < <(user_tasks "$suite")
  echo "$suite: ${#tasks[@]} user tasks in $SHARDS shards"
  for ((k = 0; k < SHARDS; k++)); do
    args=()
    for ((i = k; i < ${#tasks[@]}; i += SHARDS)); do args+=(--user-task "${tasks[i]}"); done
    if [ ${#args[@]} -eq 0 ]; then continue; fi
    (
      export LOGSUB=shard-$k # own log folder per process (see run_attacks below)
      bench benign "$suite-$k" --suite "$suite" "${args[@]}"
      bench attack "$suite-$k" --suite "$suite" "${args[@]}" --attack important_instructions
    ) &
    pids+=($!)
  done
  for i in "${pids[@]}"; do wait "$i" || failed=1; done
  return $failed
}

# Custom attacks: deal ATTACK_USER_TASKS round-robin into $SHARDS processes; each runs every attack in
# ATTACKS against INJECTION_TASKS on its share. --module-to-load registers our attacks and tasks.
# Each process gets its own log folder (runs/attack/shard-<k>): every process first runs the injection
# task as a plain user task and saves it to the same file name, and with a shared folder one process
# could read another's half-written file and crash (JSONDecodeError, job 23527077).
run_attacks() {
  local k i a pids=() failed=0
  local -a tasks args mods injs
  read -r -a tasks <<<"$ATTACK_USER_TASKS"
  mods=()
  for a in $MODULES; do mods+=(--module-to-load "$a"); done
  injs=()
  for a in $INJECTION_TASKS; do injs+=(--injection-task "$a"); done
  echo "attack: ${#tasks[@]} user tasks x [$ATTACKS] x [$INJECTION_TASKS] in $SHARDS shards"
  for ((k = 0; k < SHARDS; k++)); do
    args=()
    for ((i = k; i < ${#tasks[@]}; i += SHARDS)); do args+=(--user-task "${tasks[i]}"); done
    if [ ${#args[@]} -eq 0 ]; then continue; fi
    (
      rc=0
      export LOGSUB=shard-$k
      for a in $ATTACKS; do
        bench attack "banking-$k" --suite banking "${mods[@]}" "${injs[@]}" "${args[@]}" --attack "$a" || rc=1
      done
      exit $rc
    ) &
    pids+=($!)
  done
  for i in "${pids[@]}"; do wait "$i" || failed=1; done
  return $failed
}

status=0 # a failed shard still lets the others finish and the summary print
case "$MODE" in
  smoke) # pay a bill, a read-only question, then the bill payment with an injection in the bill
    bench benign smoke --suite banking --user-task user_task_0 --user-task user_task_1 || status=1
    bench attack smoke --suite banking --user-task user_task_0 --injection-task injection_task_0 \
      --attack important_instructions || status=1
    ;;
  baseline)
    for suite in $SUITES; do run_suite "$suite" || status=1; done
    ;;
  attack)
    run_attacks || status=1
    ;;
  *) echo "MODE must be smoke, baseline or attack (got '$MODE')" >&2; exit 2 ;;
esac

python3 "$(dirname "$0")/summarize.py" "$OUT" | tee "$OUT/results.txt"
exit $status
