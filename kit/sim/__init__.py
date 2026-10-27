"""Scenario simulator (docs/kit/simulator.md).

Offline (docs/kit/simulator.md §1, §8): kit.sim.write turns the
`simulator:` config into a high-level scenario.hl.yaml (format in kit.sim.hl),
kit.sim.compile turns that into scenario.jsonl on a kit.sim.engine, and
kit.sim.generate does both; kit.sim.truth computes ground truth from it. The modules
here are pure Python and shared with the runtime agents and the controller.
"""
