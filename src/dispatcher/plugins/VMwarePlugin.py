#
# Copyright 2016 iXsystems, Inc.
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

import ssl
from pyVim import connect
from pyVmomi import vim
from freenas.dispatcher.rpc import SchemaHelper as h, generator, accepts, returns, description
from freenas.utils import normalize
from task import Provider, Task, TaskDescription, ProgressTask, query


class VMwareProvider(Provider):
    @generator
    @accepts(str, str, str)
    @returns(h.ref('vmware-datastore'))
    def get_datastores(self, address, username, password):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        ssl_context.verify_mode = ssl.CERT_NONE
        si = connect.SmartConnect(host=address, user=username, pwd=password, sslContext=ssl_context)
        content = si.RetrieveContent()
        vm_view = content.viewManager.CreateContainerView(content.rootFolder, vim.VirtualMachine, True)

        try:
            for datastore in content.viewManager.CreateContainerView(content.rootFolder, vim.Datastore, True).view:
                vms = []
                for vm in vm_view.view:
                    if datastore not in vm.datastore:
                        continue

                    vms.append({
                        'id': vm.config.uuid,
                        'name': vm.summary.config.name,
                        'on': vm.summary.runtime.powerState == 'poweredOn',
                        'snapshottable': can_be_snapshotted(vm)
                    })

                yield {
                    'id': datastore.info.url,
                    'name': datastore.info.name,
                    'free_space': datastore.info.freeSpace,
                    'virtual_machines': vms
                }
        finally:
            connect.Disconnect(si)


class VMwareDatasetsProvider(Provider):
    @generator
    @query('vmware-dataset')
    def query(self, filter=None, params=None):
        return self.datastore.query_stream('vmware.datasets', *(filter or []), **(params or {}))


@accepts(h.all_of(
    h.ref('vmware-dataset'),
    h.required('name', 'dataset', 'datastore', 'peer')
))
class VMWareDatasetCreateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating VMware dataset mapping"

    def describe(self, dataset):
        return TaskDescription("Creating VMware datastore mapping for {name}", name=dataset['datastore'])

    def verify(self, dataset):
        return ['system']

    def run(self, dataset):
        normalize(dataset, {
            'vm_filter_op': 'ALL',
            'vm_filter_entries': []
        })

        id = self.datastore.insert('vmware.datasets', dataset)
        self.dispatcher.emit_event('vmware.dataset.changed', {
            'operation': 'create',
            'ids': [id]
        })

        return id


class VMWareDatasetUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        pass

    def describe(self, id, updated_fields):
        pass

    def verify(self, id, updated_fields):
        pass

    def run(self, id, updated_fields):
        pass


class VMWareDatasetDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        pass

    def describe(self, id):
        pass

    def verify(self, id):
        pass

    def run(self, id):
        pass


class CreateVMSnapshotsTask(ProgressTask):
    @classmethod
    def early_describe(cls, dataset):
        pass

    def verify(self, dataset):
        pass

    def run(self, dataset):
        pass


class DeleteVMSnapshotsTask(ProgressTask):
    @classmethod
    def early_describe(cls, dataset):
        pass

    def verify(self, dataset):
        pass

    def run(self, dataset):
        pass


def can_be_snapshotted(vm):
    for device in vm.config.hardware.device:
        if isinstance(device, vim.VirtualPCIPassthrough):
            return False

        # consider supporting more cases of VMs that can't be snapshoted
        # https://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1006392

    return True


def _init(dispatcher, plugin):
    plugin.register_schema_definition('vmware-datastore', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'free_space': {'type': 'integer'},
            'virtual_machines': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'additionalProperties': False,
                    'properties': {
                        'id': {'type': 'string'},
                        'name': {'type': 'string'}
                    }
                }
            }
        }
    })

    plugin.register_schema_definition('vmware-dataset-filter-op', {
        'type': 'string',
        'enum': ['NONE', 'INCLUDE', 'EXCLUDE']
    })

    plugin.register_schema_definition('vmware-dataset', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'dataset': {'type': 'string'},
            'datastore': {'type': 'string'},
            'peer': {'type': 'string'},
            'vm_filter_op': {'$ref': 'vmware-dataset-filter-op'},
            'vm_filter_entries': {
                'type': 'array',
                'items': {'type': 'string'}
            }
        }
    })

    plugin.register_provider('vmware', VMwareProvider)
    plugin.register_provider('vmware.dataset', VMwareDatasetsProvider)

    plugin.register_task_handler('vmware.dataset.create', VMWareDatasetCreateTask)
    plugin.register_task_handler('vmware.dataset.update', VMWareDatasetUpdateTask)
    plugin.register_task_handler('vmware.dataset.delete', VMWareDatasetDeleteTask)

    plugin.register_event_type('vmware.dataset.changed')
