#!/usr/bin/env bash
# Reproducible Qwen3.8-27B + AgentDojo prompt-injection baseline.
#
#   ./make.sh setup      get the image and the pinned weights ready
#   ./make.sh smoke      2 benign workspace tasks + 1 injection: checks tool calling end to end
#   ./make.sh baseline   all 4 suites: benign utility, then the important_instructions attack
#   ./make.sh attack     custom attacks from harness/ on Banking (ATTACKS, ATTACK_USER_TASKS, ...)
#   ./make.sh all        setup, then smoke, then baseline
#   ./make.sh status     your queued jobs + the tail of the newest run's logs
#   ./make.sh results    per-suite numbers from the newest run (or RUN_DIR)
#
# On Zaratan (sbatch on PATH), run it from a login node. Compute nodes have no Internet, so
# setup downloads there (the image, built as a sandbox on the login node's local disk and
# saved to scratch as one tar, plus the weights) and queues a CPU job that packs the tar into
# a .sif. smoke and baseline are GPU jobs on one A100, charged to cmsc848n-class; `all`
# chains everything with job dependencies.
# Anywhere else the same steps run in the foreground with Docker and an NVIDIA GPU.
#
# Settings (environment variables):
#   PROFILE=a100       one 40 GB A100, 48 SU/h (the class default). h100: one H100, 144 SU/h;
#                      the class asks that H100s be used only when a project needs them
#   SUITES=banking     AgentDojo suites for baseline (the project's focus); all = all four
#   SHARDS=4           parallel AgentDojo processes per suite, sharing one vLLM server
#   THINKING=low       Qwen3.8 reasoning effort: off | low | medium | xhigh
#   MAX_MODEL_LEN      context length (a100: 32768, h100: 65536)
#   ENFORCE_EAGER      1 = no CUDA graphs: slower, but fits the 40 GB A100 (a100: 1, h100: 0)
#   TIME_LIMIT         Slurm walltime for smoke / baseline (default 00:30:00 / 02:00:00,
#                      06:00:00 with SUITES=all)
#   RUN_DIR            reuse a run directory; AgentDojo skips the tasks it already finished there
#   ATTACKS            attack: space-separated attack names (default: argswap_notice argswap_policy
#                      important_instructions); INJECTION_TASKS (default injection_task_100);
#                      ATTACK_USER_TASKS (default: the 10 Banking tasks in harness/wsa_attacks.py);
#                      MODULES (default wsa_attacks, from harness/)
#   DEFENSE            baseline/attack: tool_filter | spotlighting_with_delimiting | repeat_user_prompt
#                      (empty = no defense; transformers_pi_detector needs an image rebuild)
#   SHARED             where the image, weights and runs live (Zaratan default: the class's
#                      shared scratch, so the group keeps one copy of the 31 GB weights)
set -euo pipefail
shopt -s inherit_errexit 2>/dev/null || true # bash 4.4+: keep set -e inside $(...)
cd "$(dirname "$0")"
REPO=$PWD
ROOT=$(dirname "$REPO") # repo root, which holds harness/

ACCOUNT=cmsc848n-class
PROFILE=${PROFILE:-a100}
THINKING=${THINKING:-low}
SUITES=${SUITES:-banking}
SHARDS=${SHARDS:-4}
ATTACKS=${ATTACKS:-argswap_notice argswap_policy important_instructions}
INJECTION_TASKS=${INJECTION_TASKS:-injection_task_100}
ATTACK_USER_TASKS=${ATTACK_USER_TASKS:-user_task_0 user_task_2 user_task_3 user_task_4 user_task_5 user_task_6 user_task_9 user_task_11 user_task_12 user_task_15}
MODULES=${MODULES:-wsa_attacks}
DEFENSE=${DEFENSE:-}
case "$DEFENSE" in # checked again inside the job; failing here saves a queue wait
  "" | tool_filter | spotlighting_with_delimiting | repeat_user_prompt) ;;
  transformers_pi_detector) echo "DEFENSE=transformers_pi_detector needs an image rebuild (torch, transformers, weights)" >&2; exit 2 ;;
  *) echo "DEFENSE must be empty, tool_filter, spotlighting_with_delimiting or repeat_user_prompt (got '$DEFENSE')" >&2; exit 2 ;;
esac
BENCHMARK_VERSION=v1.2.2
# FP8 for both profiles, so there is a single copy of the weights. A100s have no FP8 units;
# vLLM runs the checkpoint as weight-only FP8 (W8A16) through its Marlin kernels.
MODEL=Qwen/Qwen3.8-27B-FP8
MODEL_REVISION=017b9c7af6b5689d5dd426a76e0bc077eb5ca20a
GPU_MEM_UTIL=${GPU_MEM_UTIL:-0.90}
# Each sequence carries a large linear-attention state, so a low cap leaves room for KV cache.
# AgentDojo runs at most 4 suites in parallel.
MAX_NUM_SEQS=${MAX_NUM_SEQS:-8}

case "$PROFILE" in
  a100) GPUS=a100:1 MAX_MODEL_LEN=${MAX_MODEL_LEN:-32768} ENFORCE_EAGER=${ENFORCE_EAGER:-1} ;;
  h100) GPUS=h100:1 MAX_MODEL_LEN=${MAX_MODEL_LEN:-65536} ENFORCE_EAGER=${ENFORCE_EAGER:-0} ;;
  *) echo "PROFILE must be a100 or h100 (got '$PROFILE')" >&2; exit 2 ;;
esac

VLLM_IMAGE=$(sed -n 's/^ARG VLLM_IMAGE=//p' Dockerfile)
# Named by a hash of everything that goes into the image, so it is rebuilt only when one of
# these files changes.
IMAGE_HASH=$(cat Dockerfile apptainer.def docker/install_agentdojo.sh docker/agentdojo.lock.txt |
  { sha256sum 2>/dev/null || shasum -a 256; } | cut -c1-12)

if command -v sbatch >/dev/null; then
  BACKEND=slurm
  SHARED=${SHARED:-/scratch/zt1/project/cmsc848n/shared/proj05_agentdojo}
  SIF=$SHARED/images/agentdojo-$IMAGE_HASH.sif
  SANDBOX_TAR=$SHARED/images/agentdojo-$IMAGE_HASH.sandbox.tar
elif command -v docker >/dev/null; then
  BACKEND=docker
  SHARED=${SHARED:-$REPO/.cache}
  IMAGE=cmsc848n-agentdojo:$IMAGE_HASH
else
  echo "need Slurm + Apptainer (Zaratan) or Docker" >&2
  exit 1
fi
RUNS=$SHARED/runs
CACHE=$SHARED/cache/$USER # compile caches, per user so nobody trips over someone else's files
export HF_HOME=$SHARED/hf XDG_CACHE_HOME=$CACHE TRITON_CACHE_DIR=$CACHE/triton
umask 002 # group-writable, so teammates can reuse the image, weights and runs

die() { echo "$*" >&2; exit 1; }

need_apptainer() {
  command -v apptainer >/dev/null && return
  type module >/dev/null 2>&1 || source /usr/share/Modules/init/bash
  module load apptainer
}

# run_in_image [--gpu] <command...>
run_in_image() {
  local gpu=
  if [ "${1:-}" = --gpu ]; then gpu=1; shift; fi
  if [ "$BACKEND" = slurm ]; then
    need_apptainer
    # FETCH_IMAGE: the login-node sandbox, used to download weights before the .sif exists
    apptainer exec ${gpu:+--nv} --bind /scratch "${FETCH_IMAGE:-$SIF}" "$@"
  else
    local envs=() v
    for v in HF_HOME XDG_CACHE_HOME TRITON_CACHE_DIR HF_HUB_OFFLINE TRANSFORMERS_OFFLINE \
      VLLM_NO_USAGE_STATS DO_NOT_TRACK MODE OUT MODEL MODEL_REVISION THINKING MAX_MODEL_LEN \
      GPU_MEM_UTIL MAX_NUM_SEQS ENFORCE_EAGER BENCHMARK_VERSION SUITES SHARDS \
      ATTACKS INJECTION_TASKS ATTACK_USER_TASKS MODULES DEFENSE; do
      if [ -n "${!v:-}" ]; then envs+=(-e "$v=${!v}"); fi
    done
    docker run --rm ${gpu:+--gpus all --ipc=host} -v "$ROOT:$ROOT" -v "$SHARED:$SHARED" -w "$REPO" \
      ${envs[@]+"${envs[@]}"} "$IMAGE" "$@"
  fi
}

weights_dir() { echo "$HF_HOME/hub/models--${MODEL//\//--}/snapshots/$MODEL_REVISION"; }

download_weights() {
  mkdir -p "$HF_HOME"
  run_in_image python3 -c 'import sys
from huggingface_hub import snapshot_download
print(snapshot_download(sys.argv[1], revision=sys.argv[2]))' "$MODEL" "$MODEL_REVISION"
}

# Zaratan, login node: everything that needs the Internet. The image is built as a sandbox
# (plain directory) on the login node's local disk: mksquashfs can't start its threads on a
# login node, and unpacking the image's ~300k small files straight onto scratch crawls at
# under 1 MB/s. The sandbox goes to scratch as one tar, and the pack job squashes it.
step_fetch() {
  [ -z "${SLURM_JOB_ID:-}" ] || die "compute nodes have no Internet: run ./make.sh setup on a login node"
  # Login nodes allow 256 processes+threads per user but have 128 cores, so anything that
  # starts a thread per core (uv, Apptainer, the Hugging Face downloader) fails. Pinning this
  # shell to 8 cores makes everything it starts size itself to 8.
  taskset -cp 0-7 $$ >/dev/null
  need_apptainer
  local build=/tmp/$USER-agentdojo-$IMAGE_HASH
  # shellcheck disable=SC2064 # expand $build now: it's local and gone by EXIT time
  trap "chmod -R u+w '$build' 2>/dev/null; rm -rf '$build'" EXIT # never leave GBs in /tmp
  if [ -f "$SIF" ]; then
    echo "image ready: $SIF"
  elif [ -f "$SANDBOX_TAR" ] && [ ! -d "$build/sandbox" ]; then
    echo "image ready to pack: $SANDBOX_TAR"
  elif [ ! -f "$SANDBOX_TAR" ]; then
    chmod -R u+w "$build" 2>/dev/null || true
    rm -rf "$build"
    export APPTAINER_CACHEDIR=$build/cache APPTAINER_TMPDIR=$build/tmp
    mkdir -p "$APPTAINER_TMPDIR" "$(dirname "$SANDBOX_TAR")"
    nice apptainer build --fakeroot --sandbox --build-arg VLLM_IMAGE="$VLLM_IMAGE" \
      "$build/sandbox" apptainer.def
    chmod -R u+rwX "$build/sandbox" # fakeroot leaves some files unreadable to tar
    nice tar -C "$build/sandbox" -cf "$SANDBOX_TAR.partial" .
    mv "$SANDBOX_TAR.partial" "$SANDBOX_TAR"
  fi
  if [ -f "$SIF" ]; then
    download_weights
  else
    if [ ! -d "$build/sandbox" ]; then # tar exists but the local sandbox is gone
      mkdir -p "$build/sandbox"
      tar -C "$build/sandbox" -xf "$SANDBOX_TAR"
    fi
    FETCH_IMAGE=$build/sandbox download_weights
  fi
  chmod -R u+w "$build" 2>/dev/null || true
  rm -rf "$build"
}

# Zaratan, compute node: unpack the tar on local disk and squash it into the .sif (offline)
step_pack() {
  if [ -f "$SIF" ]; then echo "image already built: $SIF"; return; fi
  [ -f "$SANDBOX_TAR" ] || die "no $SANDBOX_TAR; run ./make.sh setup on a login node first"
  need_apptainer
  local work=${TMPDIR:-/tmp}/agentdojo-pack-$$
  mkdir -p "$work/sandbox"
  tar -C "$work/sandbox" -xf "$SANDBOX_TAR"
  APPTAINER_TMPDIR=$work apptainer build "$SIF.partial" "$work/sandbox"
  mv "$SIF.partial" "$SIF"
  rm -f "$SANDBOX_TAR"
  chmod -R u+w "$work"
  rm -rf "$work"
}

step_run() { # step_run smoke|baseline (on the GPU node)
  # The same step can be queued on several GPU types at once (e.g. PROFILE=a100 and h100);
  # the first one to start cancels the copies still waiting, so only one runs and is charged.
  if [ -n "${SLURM_JOB_ID:-}" ]; then
    squeue -u "$USER" -h -t PENDING -n "$(job_name "$1")" -o %i | xargs -r scancel
  fi
  if [ "$BACKEND" = slurm ] && [ ! -f "$SIF" ]; then die "no image at $SIF; run ./make.sh setup first"; fi
  [ -d "$(weights_dir)" ] || die "no weights at $(weights_dir); run ./make.sh setup first"
  export MODE=$1 MODEL MODEL_REVISION THINKING MAX_MODEL_LEN GPU_MEM_UTIL MAX_NUM_SEQS ENFORCE_EAGER \
    BENCHMARK_VERSION SUITES SHARDS ATTACKS INJECTION_TASKS ATTACK_USER_TASKS MODULES DEFENSE HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 VLLM_NO_USAGE_STATS=1 DO_NOT_TRACK=1
  export OUT=${RUN_DIR:-$RUNS/$(date +%Y%m%d-%H%M%S)-$MODE-$PROFILE-think-$THINKING${DEFENSE:+-$DEFENSE}}
  mkdir -p "$OUT"
  local commit=unknown v
  if git rev-parse -q HEAD >/dev/null 2>&1; then
    commit=$(git rev-parse HEAD)$([ -z "$(git status --porcelain)" ] || echo -dirty)
  fi
  {
    echo "# $(date '+%Y-%m-%dT%H:%M:%S%z') on $(hostname) by $USER"
    echo "GIT_COMMIT=$commit"
    echo "SLURM_JOB_ID=${SLURM_JOB_ID:-}"
    for v in PROFILE MODE MODEL MODEL_REVISION THINKING MAX_MODEL_LEN GPU_MEM_UTIL MAX_NUM_SEQS \
      ENFORCE_EAGER BENCHMARK_VERSION SUITES SHARDS VLLM_IMAGE IMAGE_HASH DEFENSE; do
      echo "$v=${!v}"
    done
    if [ "$1" = attack ]; then
      for v in ATTACKS INJECTION_TASKS ATTACK_USER_TASKS MODULES; do echo "$v=\"${!v}\""; done
    fi
  } >>"$OUT/config.env"
  # keep the run's own copy of the attack code and scripts, so the run can be rebuilt from a zip checkout
  if [ "$1" = attack ]; then
    local code_dir="$OUT/code/$(date +%Y%m%d-%H%M%S)" # one copy per job, so a top-up keeps the first copy
    mkdir -p "$code_dir"
    cp "$ROOT"/harness/*.py docker/run_baseline.sh docker/summarize.py "$code_dir/"
  fi
  echo "run dir: $OUT"
  run_in_image --gpu bash docker/run_baseline.sh
}

# job_name <step>: Slurm job name. It encodes every setting that changes what the job runs, but not the
# GPU type, so the auto-cancel in step_run only drops copies of the *same* run queued on another GPU type.
# (With a plain "agentdojo-<step>" name, the first baseline to start cancelled every other pending
# baseline, e.g. jobs 23547164/5 and 23535007.)
job_name() {
  local n="agentdojo-$1-think-$THINKING-${DEFENSE:-nodefense}"
  case "$1" in
    baseline) n+="-${SUITES// /+}" ;;
    attack) n+="-$(printf '%s|%s|%s|%s' "$ATTACKS" "$ATTACK_USER_TASKS" "$INJECTION_TASKS" "$MODULES" | cksum | cut -d' ' -f1)" ;;
  esac
  if [ -n "${RUN_DIR:-}" ]; then n+="-$(printf '%s' "$RUN_DIR" | cksum | cut -d' ' -f1)"; fi
  echo "$n"
}

# submit <step> [sbatch args...]: queue `make.sh _<step>` as a job and print its id
submit() {
  local step=$1
  shift
  mkdir -p "$RUNS/slurm"
  sbatch --parsable -A "$ACCOUNT" -J "$(job_name "$step")" -o "$RUNS/slurm/$step-%j.out" "$@" \
    --wrap "$REPO/make.sh _$step"
}
# serial (single-node jobs) often starts right away while standard has a 1000+ job backlog
submit_pack() { submit pack -p standard,serial -c 8 --mem=16G -t 00:45:00 "$@"; }
submit_gpu() { # submit_gpu smoke|baseline [sbatch args...]
  local step=$1 limit=00:30:00
  shift
  if [ "$step" = baseline ]; then limit=02:00:00; fi
  if [ "$step" = baseline ] && [ "$SUITES" = all ]; then limit=06:00:00; fi
  if [ "$step" = attack ]; then limit=00:45:00; fi
  submit "$step" -p gpu --gpus="$GPUS" -c 8 --mem=64G -t "${TIME_LIMIT:-$limit}" "$@"
}

latest_run() { ls -td "$RUNS"/2*/ 2>/dev/null | head -1; }

case "${1:-help}" in
  setup)
    if [ "$BACKEND" = docker ]; then
      docker build -t "$IMAGE" . && download_weights
    else
      step_fetch # in this shell, not $(...), so any failure stops here
      if [ ! -f "$SIF" ]; then
        pack=$(submit_pack)
        echo "queued pack as job $pack; log: $RUNS/slurm/pack-$pack.out"
      fi
    fi
    ;;
  smoke | baseline | attack)
    if [ "$BACKEND" = docker ]; then
      step_run "$1"
    else
      id=$(submit_gpu "$1" "${@:2}") # extra args go to sbatch, e.g. --dependency=afterok:<id>
      echo "queued $1 as job $id; log: $RUNS/slurm/$1-$id.out"
    fi
    ;;
  all)
    if [ "$BACKEND" = docker ]; then
      docker build -t "$IMAGE" . && download_weights && step_run smoke && step_run baseline
    else
      step_fetch
      pack=
      if [ ! -f "$SIF" ]; then pack=$(submit_pack); fi
      m=$(submit_gpu smoke ${pack:+--dependency=afterok:$pack})
      b=$(submit_gpu baseline --dependency=afterok:"$m")
      echo "queued ${pack:+pack $pack -> }smoke $m -> baseline $b; logs in $RUNS/slurm/"
    fi
    ;;
  status)
    if [ "$BACKEND" = slurm ]; then squeue -u "$USER" -o '%.10i %.10P %.55j %.8T %.10M %R'; fi
    dir=$(latest_run)
    if [ -n "$dir" ]; then
      echo "== $dir"
      tail -n 3 "$dir"/*.log
    fi
    ;;
  results)
    dir=${RUN_DIR:-$(latest_run)}
    echo "== $dir"
    python3 docker/summarize.py "$dir"
    ;;
  _pack) step_pack ;;
  _smoke) step_run smoke ;;
  _baseline) step_run baseline ;;
  _attack) step_run attack ;;
  help | -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//' ;;
  *) echo "unknown command '$1'; try ./make.sh help" >&2; exit 2 ;;
esac
