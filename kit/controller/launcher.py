"""`osken-manager` replacement.

os-ken >= 4.0 no longer ships the `osken-manager` CLI (os_ken/cmd was
removed). This is the 3.1.1 manager, trimmed, on top of the same os-ken APIs:

    osken-manager [--ofp-tcp-listen-port 6653] [--verbose] app.py [app2.py ...]

With --lab2-config (or $LAB2_CONFIG) the kit apps are loaded first, so a team
runs:

    osken-manager --lab2-config configs/default.yaml controller/app.py
"""

import logging
import os

from os_ken.lib import hub
hub.patch(thread=False)

from os_ken import cfg  # noqa: E402
from os_ken import log  # noqa: E402
log.early_init_log(logging.DEBUG)

from os_ken import flags  # noqa: E402,F401  (registers os-ken CLI options)
from os_ken import __version__ as version  # noqa: E402
from os_ken.base.app_manager import AppManager  # noqa: E402
from os_ken.controller import controller  # noqa: E402,F401  (registers ofp-* options)

KIT_APPS = ['kit.controller.base_app', 'kit.controller.routing_app', 'kit.controller.notify_app']

CONF = cfg.CONF
CONF.register_cli_opts([
    cfg.ListOpt('app-lists', default=[],
                help='application module name to run'),
    cfg.MultiStrOpt('app', positional=True, default=[],
                    help='application module name to run'),
    cfg.StrOpt('pid-file', default=None, help='pid file name'),
    cfg.StrOpt('lab2-config', default=None,
               help='Lab 2 run config (default: $LAB2_CONFIG or configs/default.yaml)'),
])


def main(args=None, prog=None):
    CONF(args=args, prog=prog, project='os_ken',
         version='osken-manager (kit) %s' % version)
    log.init_log()
    logger = logging.getLogger(__name__)
    hub.patch(thread=True)

    if CONF.pid_file:
        with open(CONF.pid_file, 'w') as f:
            f.write(str(os.getpid()))

    app_lists = CONF.app_lists + CONF.app
    if CONF.lab2_config or os.environ.get('LAB2_CONFIG'):
        if CONF.lab2_config:
            os.environ['LAB2_CONFIG'] = CONF.lab2_config
        app_lists = KIT_APPS + [a for a in app_lists if a not in KIT_APPS]
    app_lists = app_lists or ['os_ken.controller.ofp_handler']
    app_mgr = AppManager.get_instance()
    app_mgr.load_apps(app_lists)
    contexts = app_mgr.create_contexts()
    services = list(app_mgr.instantiate_apps(**contexts))
    try:
        hub.joinall(services)
    except KeyboardInterrupt:
        logger.debug('Keyboard interrupt; closing apps')
    finally:
        app_mgr.close()


if __name__ == '__main__':
    main()
