# +
# Copyright 2014 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################

import sys
import errno
import os
import psutil
import re
import time
import netif

from datetime import datetime
from dateutil import tz
from dispatcher.rpc import (
    RpcException,
    SchemaHelper as h,
    accepts,
    description,
    returns
)
from lib.system import system, system_bg
from lib.freebsd import get_sysctl
from task import Provider, Task, TaskException

sys.path.append('/usr/local/lib')
from freenasOS import Configuration

KEYMAPS_INDEX = "/usr/share/syscons/keymaps/INDEX.keymaps"
ZONEINFO_DIR = "/usr/share/zoneinfo"
VERSION_FILE = "/etc/version"


@description("Provides informations about the running system")
class SystemInfoProvider(Provider):
    def __init__(self):
        self.__version = None

    @accepts()
    @returns(h.array(str))
    def uname_full(self):
        return os.uname()

    @accepts()
    @returns(str)
    @description("Return the full version string, e.g. FreeNAS-8.1-r7794-amd64.")
    def version(self):
        if self.__version is None:
            # See #9113
            conf = Configuration.Configuration()
            manifest = conf.SystemManifest()
            if manifest:
                self.__version = manifest.Version()
            else:
                with open(VERSION_FILE) as fd:
                    self.__version = fd.read().strip()

        return self.__version

    @accepts()
    @returns(float, float, float)
    def load_avg(self):
        return os.getloadavg()

    @accepts()
    @returns(h.object(properties={
        'cpu_model': str,
        'cpu_cores': int,
        'memory_size': long,
    }))
    def hardware(self):
        return {
            'cpu_model': get_sysctl("hw.model"),
            'cpu_cores': get_sysctl("hw.ncpu"),
            'memory_size': get_sysctl("hw.physmem")
        }

    @accepts()
    @returns(h.object(properties={
        'system_time': str,
        'boot_time': str,
        'uptime': str,
        'timezone': str,
    }))
    def time(self):
        boot_time = datetime.fromtimestamp(psutil.BOOT_TIME, tz=tz.tzlocal())
        return {
            'system_time': datetime.now(tz=tz.tzlocal()).isoformat(),
            'boot_time': boot_time.isoformat(),
            'uptime': (datetime.now(tz=tz.tzlocal()) - boot_time).total_seconds(),
            'timezone': time.tzname[time.daylight],
        }


@description("Provides informations about general system settings")
class SystemGeneralProvider(Provider):

    @accepts()
    @returns(h.ref('system-general'))
    def get_config(self):
        return {
            'hostname': self.dispatcher.configstore.get('system.hostname'),
            'language': self.dispatcher.configstore.get('system.language'),
            'timezone': self.dispatcher.configstore.get('system.timezone'),
            'syslog_server': self.dispatcher.configstore.get('system.syslog_server'),
            'console_keymap': self.dispatcher.configstore.get('system.console.keymap')
        }

    @accepts()
    @returns(h.array(h.array(str)))
    def keymaps(self):
        if not os.path.exists(KEYMAPS_INDEX):
            return []

        rv = []
        with open(KEYMAPS_INDEX, 'r') as f:
            d = f.read()
        fnd = re.findall(r'^(?P<name>[^#\s]+?)\.kbd:en:(?P<desc>.+)$', d, re.M)
        for name, desc in fnd:
            rv.append((name, desc))
        return rv

    @accepts()
    @returns(h.array(str))
    def timezones(self):
        result = []
        for root, _, files in os.walk(ZONEINFO_DIR):
            for f in files:
                if f in (
                    'zone.tab',
                ):
                    continue
                result.append(os.path.join(root, f).replace(
                    ZONEINFO_DIR + '/', '')
                )
        return result


@description("Provides informations about UI system settings")
class SystemUIProvider(Provider):

    @accepts()
    @returns(h.ref('system-ui'))
    def get_config(self):

        protocol = []
        if self.dispatcher.configstore.get('service.nginx.http.enable'):
            protocol.append('HTTP')
        if self.dispatcher.configstore.get('service.nginx.https.enable'):
            protocol.append('HTTPS')

        return {
            'webui_procotol': protocol,
            'webui_listen': self.dispatcher.configstore.get(
                'service.nginx.listen',
            ),
            'webui_http_port': self.dispatcher.configstore.get(
                'service.nginx.http.port',
            ),
            'webui_https_port': self.dispatcher.configstore.get(
                'service.nginx.https.port',
            ),
        }


@accepts(h.ref('system-general'))
class SystemGeneralConfigureTask(Task):

    def describe(self):
        return "System General Settings Configure"

    def verify(self, props):
        return ['system']

    def run(self, props):
        if 'hostname' in props:
            netif.set_hostname(props['hostname'])

        if 'language' in props:
            self.dispatcher.configstore.set(
                'system.language',
                props['language'],
            )

        if 'timezone' in props:
            self.dispatcher.configstore.set(
                'system.timezone',
                props['timezone'],
            )

        if 'console_keymap' in props:
            self.dispatcher.configstore.set(
                'system.console.keymap',
                props['console_keymap'],
            )

        try:
            self.dispatcher.call_sync(
                'etcd.generation.generate_group', 'localtime'
            )
        except RpcException, e:
            raise TaskException(
                errno.ENXIO,
                'Cannot reconfigure system: {0}'.format(str(e),)
            )

        self.dispatcher.dispatch_event('system.general.changed', {
            'operation': 'update',
        })


@accepts(h.ref('system-ui'))
class SystemUIConfigureTask(Task):

    def describe(self):
        return "System UI Settings Configure"

    def verify(self, props):
        return ['system']

    def run(self, props):
        self.dispatcher.configstore.set(
            'service.nginx.http.enable',
            True if 'HTTP' in props.get('webui_protocol') else False,
        )
        self.dispatcher.configstore.set(
            'service.nginx.https.enable',
            True if 'HTTPS' in props.get('webui_protocol') else False,
        )
        self.dispatcher.configstore.set(
            'service.nginx.listen',
            props.get('webui_listen'),
        )
        self.dispatcher.configstore.set(
            'service.nginx.http.port',
            props.get('webui_http_port'),
        )
        self.dispatcher.configstore.set(
            'service.nginx.https.port',
            props.get('webui_https_port'),
        )

        try:
            self.dispatcher.call_sync(
                'etcd.generation.generate_group', 'nginx'
            )
            self.dispatcher.call_sync('services.reload', 'nginx')
        except RpcException, e:
            raise TaskException(
                errno.ENXIO,
                'Cannot reconfigure system UI: {0}'.format(str(e),)
            )

        self.dispatcher.dispatch_event('system.ui.changed', {
            'operation': 'update',
            'ids': ['system.ui'],
        })


@accepts()
@description("Reboots the System after a delay of 10 seconds")
class SystemRebootTask(Task):
    def describe(self):
        return "System Reboot"

    def verify(self):
        return ['root']

    def run(self, delay=10):
        self.dispatcher.dispatch_event('power.changed', {
            'operation': 'reboot',
            })
        system_bg("/bin/sleep %s && /sbin/shutdown -r now &" % delay,
                  shell=True)


@accepts()
@description("Shuts the system down after a delay of 10 seconds")
class SystemHaltTask(Task):
    def describe(self):
        return "System Shutdown"

    def verify(self):
        return ['root']

    def run(self, delay=10):
        self.dispatcher.dispatch_event('power.changed', {
            'operation': 'shutdown',
            })
        system_bg("/bin/sleep %s && /sbin/shutdown -p now &" % delay,
                  shell=True)


def _init(dispatcher, plugin):
    def on_hostname_change(args):
        if 'hostname' not in args:
            return

        dispatcher.configstore.set('system.hostname', args['hostname'])
        dispatcher.dispatch_event('system.general.changed', {
            'operation': 'update',
        })

    # Register schemas
    plugin.register_schema_definition('system-general', {
        'type': 'object',
        'properties': {
            'hostname': {'type': 'string'},
            'language': {'type': 'string'},
            'timezone': {'type': 'string'},
            'console_keymap': {'type': 'string'},
            'syslog_server': {'type': 'string'},
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('system-ui', {
        'type': 'object',
        'properties': {
            'webui_protocol': {
                'type': ['array'],
                'items': {
                    'type': 'string',
                    'enum': ['HTTP', 'HTTPS'],
                },
            },
            'webui_listen': {
                'type': ['array'],
                'items': {'type': 'string'},
            },
            'webui_http_port': {'type': 'integer'},
            'webui_https_port': {'type': 'integer'},
        },
        'additionalProperties': False,
    })

    # Register event handler
    plugin.register_event_handler('system.hostname.change', on_hostname_change)

    # Register providers
    plugin.register_provider("system.general", SystemGeneralProvider)
    plugin.register_provider("system.info", SystemInfoProvider)
    plugin.register_provider("system.ui", SystemUIProvider)

    # Register task handlers
    plugin.register_task_handler("system.general.configure", SystemGeneralConfigureTask)
    plugin.register_task_handler("system.ui.configure", SystemUIConfigureTask)
    plugin.register_task_handler("system.shutdown", SystemHaltTask)
    plugin.register_task_handler("system.reboot", SystemRebootTask)

    # Set initial hostname
    netif.set_hostname(dispatcher.configstore.get('system.hostname'))
