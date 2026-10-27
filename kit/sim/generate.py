"""Scenario generator: `simulator:` config + seed -> scenario.jsonl.

    python -m kit.sim.generate -c configs/default.yaml -o runs/x/scenario.jsonl

The two pipeline steps in one go (docs/kit/simulator.md §1):
kit.sim.write turns the config into a high-level scenario, and
kit.sim.compile turns that into the low-level timeline. Run them
separately to inspect or edit the scenario.hl.yaml in between.
"""

import argparse
import sys

from kit.config import load_config, load_topology_for
from kit.sim import timeline
from kit.sim.compile import Compiler
from kit.sim.write import Writer


class Generator:
    """write + compile for one config; after run(), `world` and `counts` are the
    compiled run's."""

    def __init__(self, cfg, topo, seed=None, duration_s=None):
        self.cfg = cfg
        self.topo = topo
        self.seed = seed
        self.duration_s = duration_s
        self.world = None
        self.counts = {}
        self.report = None

    def run(self):
        """Raises kit.sim.compile.CompileError if a check fails (self.report has them)."""
        doc = Writer(self.cfg, self.topo, self.seed, self.duration_s).run()
        c = Compiler(doc, self.topo)
        self.report = c.report
        header, events = c.run()
        self.world, self.counts = c.world, c.e.counts
        return header, events


def generate(cfg, topo=None, seed=None, duration_s=None):
    """(header, events) for a loaded run config."""
    topo = topo or load_topology_for(cfg)
    return Generator(cfg, topo, seed, duration_s).run()


def main(argv=None):
    ap = argparse.ArgumentParser(prog='python -m kit.sim.generate', description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('-c', '--config', default='configs/default.yaml')
    ap.add_argument('-o', '--out', required=True)
    ap.add_argument('--seed', type=int)
    ap.add_argument('--duration', type=float)
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    gen = Generator(cfg, load_topology_for(cfg), args.seed, args.duration)
    header, events = gen.run()
    timeline.validate(header, events)
    timeline.write(args.out, header, events)
    for line in gen.report.lines():
        print(line, file=sys.stderr)
    summary = ', '.join('%s=%d' % kv for kv in sorted(gen.counts.items()))
    print('%s: %d events (%s); %d warnings' % (args.out, len(events), summary,
                                              gen.report.total('W')), file=sys.stderr)


if __name__ == '__main__':
    main()
