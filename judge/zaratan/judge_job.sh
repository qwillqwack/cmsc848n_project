#!/usr/bin/env bash
# Zero-shot Qwen3.8-27B judge over the call dataset, on one A100. Submit from a Zaratan login node:
#   sbatch --parsable /scratch/zt1/project/cmsc848n/shared/proj05_agentdojo/judge/zaratan/judge_job.sh
# Serves the shared FP8 weights with vLLM from the shared image (thinking off), then runs score_vllm.py.
# Scores land in judge/scores/, logs in judge/slurm/.
#SBATCH -A cmsc848n-class
#SBATCH -p gpu
#SBATCH --gpus=a100:1
#SBATCH -c 8
#SBATCH --mem=64G
#SBATCH -t 01:00:00
#SBATCH -J agentdojo-judge-qwen-zeroshot
#SBATCH -o /scratch/zt1/project/cmsc848n/shared/proj05_agentdojo/judge/slurm/judge-%j.out
set -euo pipefail
SHARED=/scratch/zt1/project/cmsc848n/shared/proj05_agentdojo
JUDGE=${JUDGE:-$SHARED/judge} # sbatch runs a spooled copy of this file, so don't rely on $0
SIF=$SHARED/images/agentdojo-7995ab7c1c2b.sif
MODEL=Qwen/Qwen3.8-27B-FP8
MODEL_REVISION=017b9c7af6b5689d5dd426a76e0bc077eb5ca20a
SERVED=qwen3.8-27b

if [ "${1:-}" != inside ]; then
  command -v apptainer >/dev/null || { type module >/dev/null 2>&1 || source /usr/share/Modules/init/bash; module load apptainer; }
  export HF_HOME=$SHARED/hf XDG_CACHE_HOME=$SHARED/cache/$USER TRITON_CACHE_DIR=$SHARED/cache/$USER/triton
  export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 VLLM_NO_USAGE_STATS=1 DO_NOT_TRACK=1
  export JUDGE MODEL MODEL_REVISION SERVED
  exec apptainer exec --nv --bind /scratch "$SIF" bash "$JUDGE/zaratan/judge_job.sh" inside
fi

# Inside the image.
# Two copies of this job may sit in the queue (a shorter one backfills sooner). Whichever starts first
# takes the lock and scores; the other finds the lock or the done marker and exits before loading the model.
LOCK=$JUDGE/scores/qwen.lock
DONE=$JUDGE/scores/qwen.done
if [ -e "$DONE" ] || ! mkdir "$LOCK" 2>/dev/null; then
  echo "judge already done ($DONE) or running elsewhere ($LOCK); nothing to do"
  exit 0
fi
server=
cleanup() {
  if [ -n "$server" ]; then kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true; fi
  [ -e "$DONE" ] || rmdir "$LOCK" 2>/dev/null || true # failed or cut short: let the other copy try
}
trap cleanup EXIT
trap 'exit 143' TERM INT

PORT=$((20000 + RANDOM % 20000))
LOG=$JUDGE/slurm/vllm-${SLURM_JOB_ID:-local}.log
vllm serve "$MODEL" --revision "$MODEL_REVISION" --served-model-name "$SERVED" \
  --max-model-len 32768 --gpu-memory-utilization 0.90 --max-num-seqs 8 --enforce-eager \
  --language-model-only --reasoning-parser qwen3 --max-logprobs 20 \
  --default-chat-template-kwargs '{"enable_thinking": false}' \
  --port "$PORT" >"$LOG" 2>&1 &
server=$!
echo "waiting for vLLM on :$PORT (log: $LOG)"
for _ in $(seq 360); do
  curl -sf "http://localhost:$PORT/health" >/dev/null && break
  if ! kill -0 "$server" 2>/dev/null; then echo "vLLM exited during startup:" >&2; tail -40 "$LOG" >&2; exit 1; fi
  sleep 5
done
curl -sf "http://localhost:$PORT/health" >/dev/null || { echo "vLLM not healthy after 30 min" >&2; exit 1; }
echo "vLLM is up"
/opt/agentdojo/bin/python "$JUDGE/zaratan/score_vllm.py" --data "$JUDGE/calls.jsonl" \
  --out-dir "$JUDGE/scores" --model "$SERVED" --port "$PORT" --workers 8
touch "$DONE"
