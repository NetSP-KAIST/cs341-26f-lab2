# CS.30401 Network Lab 2: lab kit

This is the lab kit for Lab 2, Network Filtering with SDN. It plays a
scenario in an emulated ISP network (Mininet and Open vSwitch) with your
os-ken controller, enforces the lab's budgets, and logs every request with
its ground truth.

- The task and the rules are in the main document, and your VM, the default
  settings, the budget values and a first run are in the Lab Environment
  Guide. Both are on KLMS.
- `docs/kit/openflow-surface.md`: what your controller may do, the kit
  events and lookups, and how the budgets are enforced.
- `docs/kit/simulator.md`: scenarios, events, ground truth and logs.
- `docs/kit/scenario.hl.example.yaml`: an annotated scenario file.

| Path | What |
|---|---|
| `controller/` | your team's workspace; `app.py` is a skeleton controller |
| `kit/` | the kit: simulator, controller layer, budget enforcement |
| `configs/default.yaml` | the run config: budgets, pipeline, scenario settings |
| `presets/` | example scenarios: `quiet`, `evasion`, `crackdown`, `surge` |
| `topologies/isp_v2.yaml` | the network |

A first run, with the skeleton controller (it logs kit events and blocks
nothing):

```sh
sudo .venv/bin/python -m kit.run -c configs/default.yaml \
    --app controller/app.py --run-id first
```

Write your controller in `controller/`, and keep your configs and scripts
there too. Do not modify anything else. Update the kit with `git pull`.
