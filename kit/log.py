"""Structured run logs (JSONL); the files are listed in docs/kit/simulator.md §5.

Each process writes its own files under <logging.out_dir>/<run_id>/.
run_id: logging.run_id, or $LAB2_RUN_ID, or a UTC timestamp.
"""

import json
import os
import time
from pathlib import Path

from kit.config import resolve_path


def run_dir(cfg):
    lc = cfg['logging']
    run_id = os.environ.get('LAB2_RUN_ID') or lc.get('run_id') or 'auto'
    if run_id == 'auto':
        run_id = time.strftime('%Y%m%d-%H%M%S', time.gmtime())
        os.environ['LAB2_RUN_ID'] = run_id      # child processes share it
    d = resolve_path(lc.get('out_dir', 'runs/')) / run_id
    d.mkdir(parents=True, exist_ok=True)
    return d


class JsonlLog:
    def __init__(self, path):
        self.path = Path(path)
        self.f = open(self.path, 'a', buffering=1)

    def write(self, ev, **fields):
        rec = {'t': round(time.time(), 6), 'ev': ev}
        rec.update(fields)
        self.f.write(json.dumps(rec, default=str) + '\n')

    def close(self):
        self.f.close()


class NullLog:
    def write(self, ev, **fields):
        pass

    def close(self):
        pass
