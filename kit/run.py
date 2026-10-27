"""One run: a scenario in, outcomes out (simulator.md §1).

    sudo .venv/bin/python -m kit.run -c configs/default.yaml --scenario my/scenario.hl.yaml \\
        --app controller/app.py

Starts the kit controller with the team's app(s), the network with the
scenario's prefixes, the simulator agents and the orchestrator; plays the
timeline once; stops everything; then writes runs/<run_id>/outcomes.jsonl
(kit.sim.truth). Everything the run produced is under runs/<run_id>/
(simulator.md §5).

--scenario takes a scenario.hl.yaml (compiled first, kit.sim.compile; --seed
reseeds its request sampling) or a compiled scenario.jsonl (played as is).
Without --scenario, one is written from the config's `simulator:` section
(kit.sim.write; --seed, --duration) and compiled.

--controller external: start the controller yourself (e.g. under a
debugger); the command prints what to run and waits for it.
"""

import argparse
import json
import os
import pwd
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path

from kit.config import REPO_ROOT, load_config, load_topology_for, resolve_path
from kit.sim import timeline, truth
from kit.sim.agent import DRAIN_S

CONNECT_TIMEOUT_S = 60
EXTERNAL_WAIT_S = 600
END_MARGIN_S = 10
BOOTSTRAP_MARGIN_S = 10


def is_hl(path):
    return str(path).endswith(('.yaml', '.yml'))


def stage_scenario(cfg, run_dir, source=None, seed=None, duration=None):
    """The run's scenario files in run_dir (simulator.md §5). Returns
    (scenario.jsonl path, header, events).

    source None: written from the config's `simulator:` section (seed and
    duration override it) and compiled; source *.hl.yaml: compiled (seed
    reseeds request sampling); source *.jsonl: copied. An HL source is kept
    as scenario.hl.yaml and its check report as scenario.check.json.
    Raises kit.sim.compile.CompileError (report already written) or
    kit.sim.hl.HLError.
    """
    from kit.sim import compile as sc, hl
    out = run_dir / 'scenario.jsonl'
    if source is not None and not is_hl(source):
        header, events = timeline.read(source)
        timeline.validate(header, events)
        shutil.copy(source, out)
        return out, header, events
    hl_out = run_dir / 'scenario.hl.yaml'
    if source is None:
        from kit.sim.write import write_scenario
        topo = load_topology_for(cfg)
        doc = write_scenario(cfg, topo, seed, duration)
        hl.check(doc)
        hl.dump(doc, hl_out)
        seed = None                     # already the document's
    else:
        topo = None                     # the one the document names
        doc = hl.load(source)
        shutil.copy(source, hl_out)
    rpath = sc.check_path(str(out))
    try:
        c = sc.Compiler(doc, topo, seed)
        header, events = c.run()
    except sc.CompileError as ex:
        if ex.report is not None:
            sc.write_report(rpath, ex.report, scenario=hl_out.name)
        raise
    sc.write_report(rpath, c.report, scenario=hl_out.name)
    timeline.validate(header, events)
    timeline.write(out, header, events)
    return out, header, events


def _owner():
    """(uid, gid) of the user behind sudo, or None."""
    name = os.environ.get('SUDO_USER')
    if os.geteuid() != 0 or not name or name == 'root':
        return None
    pw = pwd.getpwnam(name)
    return pw.pw_uid, pw.pw_gid


def _chown(path, owner, recursive=False):
    if owner is None:
        return
    paths = [Path(path)]
    if recursive:
        paths += list(Path(path).rglob('*'))
    for p in paths:
        try:
            os.chown(p, *owner, follow_symlinks=False)
        except OSError:
            pass


TEAM_DIR = 'controller'           # the team's workspace: not part of the kit's dirty state


def _git(*args):
    """stdout of a git command in the kit checkout, or None without git.
    safe.directory: under sudo the checkout belongs to another user."""
    try:
        out = subprocess.run(['git', '-c', 'safe.directory=*', '-C', str(REPO_ROOT)]
                             + list(args), capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


def kit_commit():
    """`git describe --always` of the kit checkout, plus `-dirty` when tracked
    files outside controller/ differ from it; None without git."""
    desc = (_git('describe', '--always') or '').strip()
    if not desc:
        return None
    changed = _git('status', '--porcelain', '--untracked-files=no', '--',
                   '.', ':(exclude)%s' % TEAM_DIR)
    if changed is None:
        return None
    return desc + '-dirty' if changed.strip() else desc


def controller_dirty():
    """True when controller/ differs from the commit (including new files),
    None without git."""
    out = _git('status', '--porcelain', '--untracked-files=all', '--', TEAM_DIR)
    return None if out is None else bool(out.strip())


def new_run_dir(cfg, run_id=None):
    """runs/<run_id>/, owned by the sudo user so the controller can write there.
    kit.json records the kit commit and controller/ state (simulator.md §5)."""
    run_id = run_id or time.strftime('%Y%m%d-%H%M%S')
    out = resolve_path(cfg['logging'].get('out_dir', 'runs/'))
    owner = _owner()
    if not out.exists():
        out.mkdir(parents=True)
        _chown(out, owner)
    d = out / run_id
    if d.exists():
        raise SystemExit('%s already exists; pick another --run-id' % d)
    d.mkdir()
    meta = {'kit_commit': kit_commit(), 'controller_dirty': controller_dirty()}
    (d / 'kit.json').write_text(json.dumps(meta) + '\n')
    _chown(d, owner, recursive=True)
    return d


def _listening(host, port):
    try:
        socket.create_connection((host, port), timeout=0.5).close()
        return True
    except OSError:
        return False


def _wait_listening(host, port, timeout, proc=None):
    end = time.time() + timeout
    while time.time() < end:
        if proc is not None and proc.poll() is not None:
            raise RuntimeError('controller exited (%s); see controller.log' % proc.returncode)
        if _listening(host, port):
            return
        time.sleep(0.2)
    raise RuntimeError('no controller listening on %s:%d after %ds' % (host, port, timeout))


def _sigterm(signum, frame):
    raise KeyboardInterrupt


def controller_env(cfg_path, scenario, run_dir):
    return {'LAB2_CONFIG': str(cfg_path), 'LAB2_SCENARIO': str(scenario),
            'LAB2_RUN_ID': run_dir.name, 'LAB2_NOTIFY_SOCK': str(run_dir / 'notify.sock'),
            'LAB2_BOOTSTRAP': '1'}


def play(cfg_path, scenario, run_dir, apps=(), controller='kit', extra_env=None,
         on_network=None):
    """Play scenario once. on_network(net, topo, run_dir) runs after the switches
    connect, before the agents start, and may return a cleanup callable.
    Before the clock starts, the controller's bootstrap phase runs (t = 0
    state delivered, U off, until the team's ready() or the timeout).
    Returns {'clients_not_done': [...], 'not_acked': n, 'interrupted': bool,
    'bootstrap': the controller's 'bootstrap_end' summary or None}."""
    from mininet.clean import cleanup
    from mininet.log import setLogLevel
    from kit.net.build import build_network, start_network
    from kit.sim.launch import Agents
    from kit.sim.orchestrator import Orchestrator

    cfg = load_config(cfg_path)
    header = timeline.read_header(scenario)
    topo = load_topology_for(cfg, scenario)
    if header.get('topology') != topo.name:
        raise SystemExit('%s is for topology %r; the config runs %r'
                         % (scenario, header.get('topology'), topo.name))
    host, port = cfg['controller']['host'], cfg['controller']['port']
    env = dict(controller_env(cfg_path, scenario, run_dir), **(extra_env or {}))
    owner = _owner()

    if _listening(host, port):
        raise SystemExit('something already listens on %s:%d (a controller left from an '
                         'earlier run?); stop it first' % (host, port))
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, _sigterm)       # stop cleanly, like Ctrl-C
    setLogLevel('warning')
    cleanup()
    ctrl = None
    if controller == 'kit':
        cmd = [sys.executable, '-m', 'kit.controller.launcher', '--ofp-tcp-listen-port',
               str(port)] + [str(a) for a in apps]
        kw = {}
        if owner is not None:            # the team's code runs as the user, not root
            kw = {'user': owner[0], 'group': owner[1],
                  'extra_groups': os.getgrouplist(pwd.getpwuid(owner[0]).pw_name, owner[1])}
        ctrl = subprocess.Popen(cmd, env=dict(os.environ, PYTHONPATH=str(REPO_ROOT), **env),
                                stdout=open(run_dir / 'controller.log', 'w'),
                                stderr=subprocess.STDOUT, cwd=REPO_ROOT, **kw)
        _wait_listening(host, port, 20, ctrl)
    else:
        print('start the controller now, as your user:\n  %s %s --ofp-tcp-listen-port %d '
              '<your app> ...' % (' '.join('%s=%s' % (k, shlex.quote(v))
                                           for k, v in env.items()),
                                  shlex.quote(os.path.join(os.path.dirname(sys.executable),
                                                           'osken-manager')), port))
        print('waiting for it on %s:%d ...' % (host, port), flush=True)
        _wait_listening(host, port, EXTERNAL_WAIT_S)

    net = build_network(topo, cfg)
    agents = orch = None
    cleanups = []
    status = {'clients_not_done': [], 'not_acked': 0, 'interrupted': False,
              'bootstrap': None}
    boot_wait = (cfg['controller'].get('bootstrap_timeout_s', 60) or 0) + BOOTSTRAP_MARGIN_S
    try:
        start_network(net, topo, cfg)
        if not net.waitConnected(timeout=CONNECT_TIMEOUT_S):
            raise RuntimeError('switches did not connect within %ds' % CONNECT_TIMEOUT_S)
        time.sleep(1.0)
        if on_network:
            c = on_network(net, topo, run_dir)
            if c:
                cleanups.append(c)
        agents = Agents(net, topo, scenario, run_dir)
        agents.start()
        agents.wait_ready()
        orch = Orchestrator(net, header, scenario, env['LAB2_NOTIFY_SOCK'],
                            run_dir / 'orchestrator.jsonl')
        print('bootstrap: t = 0 state delivered; waiting for the team\'s ready() ...',
              flush=True)
        boot = status['bootstrap'] = orch.bootstrap(boot_wait)
        if boot and boot.get('ok'):
            print('bootstrap ended (%s) after %.1f s, %d team flow-mods' % (
                boot['ended_by'], boot['bootstrap_s'], boot['team_flow_mods']))
        else:
            print('warning: bootstrap reply missing or failed: %r' % (boot,))
        orch.start_at(agents.start_clock())
        print('playing %s (%.0f s) ...' % (scenario, header['duration_s']))
        status['clients_not_done'] = agents.wait_clients(
            header['duration_s'] + DRAIN_S + END_MARGIN_S)
        orch.done.wait(END_MARGIN_S)
        status['not_acked'] = orch.errors
    except KeyboardInterrupt:
        status['interrupted'] = True
        print('interrupted; stopping')
    finally:
        if orch:
            orch.stop()
        if agents:
            agents.stop()
        for c in cleanups:
            c()
        net.stop()
        if ctrl is not None:
            ctrl.terminate()
            try:
                ctrl.wait(5)
            except subprocess.TimeoutExpired:
                ctrl.kill()
        _chown(run_dir, owner, recursive=True)
    return status


def write_outcomes(run_dir, scenario):
    """Join the client logs with ground truth -> run_dir/outcomes.jsonl. Returns rows."""
    header, events = timeline.read(scenario)
    rows = truth.join(truth.compute(header, events), truth.read_logs([run_dir / 'requests']))
    with open(run_dir / 'outcomes.jsonl', 'w') as f:
        for r in rows:
            f.write(json.dumps(r) + '\n')
    _chown(run_dir / 'outcomes.jsonl', _owner())
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(prog='python -m kit.run', description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('-c', '--config', default='configs/default.yaml')
    ap.add_argument('--scenario',
                    help='scenario.hl.yaml (compiled first) or a compiled scenario.jsonl. '
                         'Default: written from the config and compiled')
    ap.add_argument('--app', action='append', default=None,
                    help='team os-ken app (file or module); repeatable. '
                         'Default: controller.app in the config, else none (kit apps only)')
    ap.add_argument('--controller', choices=('kit', 'external'), default='kit')
    ap.add_argument('--run-id', help='default: a timestamp')
    ap.add_argument('--seed', type=int,
                    help='with a .hl.yaml: request-sampling seed; without --scenario: '
                         'the writer\'s seed')
    ap.add_argument('--duration', type=float, help='without --scenario only')
    args = ap.parse_args(argv)
    if args.scenario and not is_hl(args.scenario) and args.seed is not None:
        ap.error('--seed needs a .hl.yaml scenario (a .jsonl is already sampled)')
    if args.scenario and args.duration is not None:
        ap.error('--duration applies only without --scenario (the scenario sets it)')
    if os.geteuid() != 0:
        sys.exit('run with sudo (Mininet needs root); the controller runs as your user')

    from kit.sim.compile import CompileError
    from kit.sim.hl import HLError
    cfg_path = resolve_path(args.config)
    cfg = load_config(cfg_path)
    apps = args.app if args.app is not None else \
        ([cfg['controller']['app']] if cfg['controller'].get('app') else [])
    apps = [os.path.abspath(a) if os.path.exists(a) else a for a in apps]
    run_dir = new_run_dir(cfg, args.run_id)
    shutil.copy(cfg_path, run_dir / 'config.yaml')
    try:
        scenario, header, events = stage_scenario(cfg, run_dir, args.scenario,
                                                  args.seed, args.duration)
    except HLError as ex:
        _chown(run_dir, _owner(), recursive=True)
        sys.exit('%s: E1 %s' % (args.scenario, ex))
    except CompileError as ex:
        _chown(run_dir, _owner(), recursive=True)
        if ex.report is not None:
            print('\n'.join(ex.report.lines()), file=sys.stderr)
        sys.exit('scenario does not compile: %s (report: %s)'
                 % (ex, run_dir / 'scenario.check.json'))
    print('scenario %s: %d events' % (scenario, len(events)))
    _chown(run_dir, _owner(), recursive=True)

    status = play(cfg_path, scenario, run_dir, apps, args.controller)
    rows = write_outcomes(run_dir, scenario)
    print('outcomes: %d requests %s' % (len(rows), dict(sorted(
        Counter(r['outcome'] for r in rows).items()))))
    problems = []
    if status['interrupted']:
        problems.append('interrupted')
    if status['clients_not_done']:
        problems.append('clients not done: %s' % ' '.join(status['clients_not_done']))
    if status['not_acked']:
        problems.append('%d controller notifications not acked (orchestrator.jsonl)'
                        % status['not_acked'])
    for p in problems:
        print('warning:', p)
    print('written:', run_dir)
    sys.exit(1 if problems else 0)


if __name__ == '__main__':
    main()
