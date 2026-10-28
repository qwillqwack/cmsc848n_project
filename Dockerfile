# vLLM (serves Qwen3.8-27B) + AgentDojo, for the prompt-injection baseline.
# Use ./make.sh rather than building this directly: it also downloads the pinned weights,
# and on Zaratan (no Docker) it builds apptainer.def, which reads its base image from the
# VLLM_IMAGE line below so the two recipes can't drift apart.

# vllm/vllm-openai:v0.32.0 (CUDA 13.0, linux/amd64), pinned by digest
ARG VLLM_IMAGE=vllm/vllm-openai@sha256:6ee133356d49ed24cee03dd0cda3d3980279a11c107ce3e752c89e76540f41c9
FROM ${VLLM_IMAGE}

# AgentDojo 0.1.35 goes in its own venv; exact deps and hashes are in the lockfile.
COPY docker/agentdojo.lock.txt docker/install_agentdojo.sh /opt/cmsc848n/
RUN bash /opt/cmsc848n/install_agentdojo.sh

# The base image's entrypoint is `vllm serve`; docker/run_baseline.sh starts the server itself.
ENTRYPOINT []
CMD ["bash"]
