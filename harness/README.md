# harness/ — Workstream A

| file | what it is |
|---|---|
| `wsa_attacks.py` | Custom argument-hijacking attacks for Banking, loaded by AgentDojo with `--module-to-load wsa_attacks`. Registers `injection_task_100` (attacker receives any payment the agent sends, schedules or updates) and two attacks: `argswap_notice` (keeps the original document and appends an in-voice "our bank account changed" note) and `argswap_policy` (appends a "bank policy: pay only this verified account" notice). Stock `important_instructions` against `injection_task_100` is the control. |
| `preflight_attacks.py` | GPU-free check, ~10 s on a login node: environments load, correct calls still solve each task, a swapped recipient is scored as hijacked; prints the attacked text. |
| `show_run.py` | Read runs yourself: lists runs where something went wrong; with `-u`/`-a` (or `--benign`) prints one conversation, injected text marked. |
| `preflight_defenses.sh` + `fake_openai_server.py` | GPU-free check (~1 min, login node) of the `DEFENSE` setting: runs AgentDojo's CLI from the image against a stand-in model server that records requests. Confirms the tool filter asks for `vllm_parsed` (and fails without the alias), delimiting wraps tool outputs in `<< >>`, and repeat-prompt repeats the request. |
| `report.sh` | One report (settings, Slurm state, tables, problem runs) for one or more run folders. |
| `analyze_runs.py` | Standard library only. Per-run CSV + summary for a run folder: ASR, utility, and whether each hijack *redirected* the user's payment or added an *extra* one (from call arguments, because AgentDojo's utility check ignores the recipient for user tasks 2, 6, 9, 11, 12). |

Run (Zaratan, login node):

    cluster/make.sh attack                   # A100, <= 45 min; settings: ATTACKS, ATTACK_USER_TASKS, INJECTION_TASKS
    cluster/make.sh results                  # per-attack table
    python3 harness/analyze_runs.py "$(ls -td /scratch/zt1/project/cmsc848n/shared/proj05_agentdojo/runs/2*attack*/ | head -1)"

`data/shared_tool_pairs_v1.2.2.csv`: T1's shared-tool flag per (suite, user task, injection task); `analyze_runs.py` uses it to report ASR on the shared-tool subset.

    python3 harness/show_run.py <run dir>                         # problem runs
    python3 harness/show_run.py <run dir> -u user_task_12 -a argswap_notice

Defenses (Workstream A task 5, table T2): `DEFENSE=tool_filter | spotlighting_with_delimiting | repeat_user_prompt`
works with `baseline` and `attack`, e.g. `THINKING=off DEFENSE=tool_filter cluster/make.sh baseline`. With
`tool_filter`, vLLM also serves the name `vllm_parsed`, because AgentDojo 0.1.35's filter asks for that name.

Note: AgentDojo 0.1.35 sends no temperature for the agent's own calls (`temperature or NOT_GIVEN` drops 0.0),
so vLLM uses the model's default sampling. Runs are not deterministic; repeat key rows to see the spread.
