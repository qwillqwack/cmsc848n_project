#!/usr/bin/env bash
# Install AgentDojo into /opt/agentdojo, a venv separate from vLLM's Python, so the two
# dependency sets can't conflict. Versions and hashes come from agentdojo.lock.txt, which was
# resolved as of AgentDojo 0.1.35's release (see the command at the top of that file).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

# The vLLM image sets these for its own environment (UV_OVERRIDE pins NCCL, which has no
# hash in our lock and breaks --require-hashes). AgentDojo's venv should see none of them.
unset UV_OVERRIDE UV_CONSTRAINT UV_BUILD_CONSTRAINT UV_INDEX_STRATEGY UV_EXTRA_INDEX_URL
export UV_CACHE_DIR=/tmp/uv-cache
# uv starts one install thread per core by default, which overruns per-user thread limits
# on shared machines like Zaratan's login nodes (256 per user, 128 cores).
export UV_CONCURRENT_INSTALLS=4 RAYON_NUM_THREADS=4
command -v uv >/dev/null || python3 -m pip install --no-cache-dir uv
uv venv --python "$(command -v python3)" /opt/agentdojo
uv pip install --python /opt/agentdojo/bin/python --require-hashes -r "$here/agentdojo.lock.txt"
rm -rf "$UV_CACHE_DIR"

/opt/agentdojo/bin/python -c "import importlib.metadata as m; print('agentdojo', m.version('agentdojo'))"
