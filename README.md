# cmsc848n_project

## AgentDojo baseline on Qwen3.8-27B

`cluster/Dockerfile` + `cluster/make.sh` set up a self-hosted Qwen3.8-27B (vLLM) and run the AgentDojo
prompt-injection suite against it. Everything is pinned: the vLLM image by digest, the model by
Hugging Face commit, AgentDojo and its dependencies by hash (`cluster/docker/agentdojo.lock.txt`).

On Zaratan, from a login node:

```bash
git clone -b cluster https://github.com/qwillqwack/cmsc848n_project.git ~/scratch/cmsc848n_project
cd ~/scratch/cmsc848n_project/cluster
./make.sh all       # download, then pack -> smoke -> baseline as chained Slurm jobs
./make.sh status    # queue + newest run's logs
./make.sh results   # per-suite utility and attack success rate
```

Compute nodes have no Internet, so `setup` (and `all`) download on the login node: the image as
an Apptainer sandbox and the FP8 weights (31 GB). A short CPU job packs the sandbox into a `.sif`.
Everything lives in `/scratch/zt1/project/cmsc848n/shared/proj05_agentdojo`, so a teammate's
`./make.sh setup` finds it and returns right away. Zaratan has no Docker; `apptainer.def` takes
its base image from the Dockerfile and runs the same install script. With Docker and an NVIDIA
GPU, the same commands run locally.

GPU jobs use one A100 (48 SU/hour on the shared `cmsc848n-class` allocation), per the course's
Zaratan rules. The FP8 checkpoint fits a 40 GB A100 as weight-only FP8. `PROFILE=h100` exists but
the course asks for H100s only when a project needs them. `./make.sh help` lists the other
settings (thinking effort, context length, walltime).

## Repository layout

| Path | What it is |
|---|---|
| `cluster/` | The runnable pipeline (Ishaan): `make.sh`, `Dockerfile`, `apptainer.def`, `docker/` and the setup guide (`SETUP.pdf`) for self-hosted Qwen3.8-27B + AgentDojo on Zaratan |
| `harness/` | Workstream A additions: custom attacks, run analysis, GPU-free checks (see `harness/README.md`) |
| `agentdojo-security-research/` | Project template for the defense (B) and attack (C) workstreams |

## Workstream A additions

- `cluster/make.sh attack`: our custom argument-hijacking attacks on Banking
- `DEFENSE=tool_filter | spotlighting_with_delimiting | repeat_user_prompt cluster/make.sh baseline` (or `attack`): add an AgentDojo built-in defense
- `THINKING=off cluster/make.sh ...`: turn the model's reasoning off
- `harness/report.sh`: summary of the newest runs; `python3 harness/show_run.py <run folder>` to read a run's conversations
- `harness/preflight_defenses.sh`, `harness/preflight_attacks.py`: checks that need no GPU; run them on a login node before submitting
