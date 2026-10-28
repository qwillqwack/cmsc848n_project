#!/usr/bin/env bash
# Does the model see AgentDojo's system prompt? AgentDojo 0.1.35 sends it with role "developer".
# Checks (login node, no GPU, ~30 s): how vLLM handles "developer", and what Qwen's chat template renders.
set -uo pipefail
P=/scratch/zt1/project/cmsc848n/shared/proj05_agentdojo
SIF=${SIF:-$P/images/agentdojo-7995ab7c1c2b.sif}
SNAP=$P/hf/hub/models--Qwen--Qwen3.8-27B-FP8/snapshots/017b9c7af6b5689d5dd426a76e0bc077eb5ca20a
command -v apptainer >/dev/null || { type module >/dev/null 2>&1 || source /usr/share/Modules/init/bash; module load apptainer; }
echo "== 1. lines in vLLM's chat code that mention 'developer'"
apptainer exec --bind /scratch "$SIF" python3 - <<'PY'
import pathlib, vllm
root = pathlib.Path(vllm.__file__).parent / "entrypoints"
for f in sorted(root.rglob("*.py")):
    for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
        if "developer" in line:
            print(f"{f.relative_to(root.parent)}:{i}: {line.strip()[:140]}")
PY
echo; echo "== 2. what Qwen's chat template renders for a 'system' vs a 'developer' message"
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 apptainer exec --bind /scratch "$SIF" python3 - "$SNAP" <<'PY'
import sys
from transformers import AutoTokenizer
tok = AutoTokenizer.from_pretrained(sys.argv[1])
for role in ["system", "developer"]:
    try:
        s = tok.apply_chat_template([{"role": role, "content": "MARKER-SYSTEM-PROMPT"},
                                     {"role": "user", "content": "hi"}],
                                    tokenize=False, add_generation_prompt=True)
        print(f"--- role={role}: marker rendered = {'MARKER-SYSTEM-PROMPT' in s}")
        print(s)
    except Exception as e:
        print(f"--- role={role}: template raised {type(e).__name__}: {e}")
PY
