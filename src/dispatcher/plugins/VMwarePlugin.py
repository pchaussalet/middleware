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

from pyVim import connect
from pyVmomi import vim
from freenas.dispatcher.rpc import generator, accepts, returns, description
from task import Provider, query


class VMwareProvider(Provider):
    @generator
    def get_datastores(self, address, username, password):
        si = connect.SmartConnect(host=address, user=username, pwd=password)
        content = si.RetrieveContent()

        for datastore in content.viewManager.CreateContainerView(content.rootFolder, vim.Datastore, True):
            yield {
                'id': datastore.url,
                'name': datastore.name,
                'free_space': datastore.freeSpace,
                'virtual_machines': []
            }


class VMwareSnapshotMappingProvider(Provider):
    @generator
    @query('vmware-dataset-mapping')
    def query(self, filter=None, params=None):
        pass


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

    plugin.register_schema_definition('vmware-dataset', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'dataset': {'type': 'string'},
            'datastore': {'type': 'string'}
        }
    })
