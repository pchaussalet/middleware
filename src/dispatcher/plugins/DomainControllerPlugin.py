# Copyright 2015 iXsystems, Inc.
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

import errno
import logging
from datastore.config import ConfigNode
from freenas.dispatcher.rpc import RpcException, SchemaHelper as h, description, accepts, returns
from task import Task, Provider, TaskException, TaskDescription


logger = logging.getLogger(__name__)


@description('Provides info about Domain Controller vm service')
class DCProvider(Provider):
    @accepts()
    @returns(h.ref('service-dc'))
    def get_config(self):
        config = ConfigNode('service.dc', self.configstore).__getstate__()
        return config

    def service_start(self):
        dc_vm = self.get_config()
        self.dispatcher.call_task_sync('vm.start', dc_vm['vm_id'])

    def service_status(self):
        dc_vm = self.get_config()
        state = self.dispatcher.call_sync(
            'vm.query',
            [('id', '=', dc_vm['vm_id'])],
            {'select': 'status.state', 'single': True}
        )
        return state

    def service_stop(self):
        dc_vm = self.get_config()
        self.dispatcher.call_task_sync('vm.stop', dc_vm['vm_id'])

    def service_restart(self):
        dc_vm = self.get_config()
        self.dispatcher.call_task_sync('vm.reboot', dc_vm['vm_id'])

    def provide_dc_url(self):
        dc_vm = self.get_config()
        if dc_vm['vm_id'] and dc_vm['enable']:
            guest_info = self.dispatcher.call_sync('vm.get_guest_info', dc_vm['vm_id'])
            addresses = []
            for name, config in guest_info['interfaces'].items():
                if name.startswith('lo'):
                    continue
                addresses += ['https://' + i['address'] + ':8443' for i in config['aliases'] if i['af'] != 'LINK']

            return addresses
        else:
            return "Please configure and enable the Domain Controller vm service."


@description('Configure Domain Controller vm service')
@accepts(h.ref('service-dc'))
class DCConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring DC service'

    def describe(self, dc):
        return TaskDescription('Configuring Domain Controller vm service')

    def verify(self, dc):
        return ['system']

    def run(self, dc):
        node = ConfigNode('service.dc', self.configstore).__getstate__()
        node.update(dc)
        if node['enable'] and not node.get('volume'):
            raise TaskException(errno.ENXIO,
                                'Domain controller service is hosted by the virutal machine.'
                                'Please provide the valid zfs pool name for the virtual machine volume creation.')

        if node['enable'] and not node['vm_id']:
            dc['vm_id'], = self.join_subtasks(self.run_subtask('vm.create', {
                'name': 'zentyal_domain_controller',
                'template': {'name': 'zentyal-4.2'},
                'target': node['volume']
            }))

        try:
            node = ConfigNode('service.dc', self.configstore)
            node.update(dc)

            self.dispatcher.dispatch_event('service.dc.changed', {
                'operation': 'update',
                'ids': None,
            })

        except RpcException as e:
            raise TaskException(errno.ENXIO,
                                'Cannot reconfigure DC vm service: {0}'.format(str(e)))


def _init(dispatcher, plugin):

    plugin.register_schema_definition('service-dc', {
        'type': 'object',
        'properties': {
            'type': {'enum': ['service-dc']},
            'enable': {'type': 'boolean'},
            'volume': {'type': 'string'},
        },
        'additionalProperties': False,
    })

    plugin.register_provider("service.dc", DCProvider)

    plugin.register_task_handler("service.dc.update", DCConfigureTask)
