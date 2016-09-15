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

import errno
import logging
from freenas.dispatcher.rpc import SchemaHelper as h, description, accepts, private, generator
from task import Task, Provider, TaskException, VerifyException, query, TaskDescription


logger = logging.getLogger(__name__)


@description('Provides information about known peers')
class PeerProvider(Provider):
    @query('peer')
    @generator
    def query(self, filter=None, params=None):
        return self.datastore.query_stream('peers', *(filter or []), **(params or {}))

    @private
    def peer_types(self):
        result = []
        for p in list(self.dispatcher.plugins.values()):
            if p.metadata and p.metadata.get('type') == 'peering':
                result.append(p.metadata.get('subtype'))

        return result


@description('Creates a peer entry')
@accepts(h.all_of(
    h.ref('peer'),
    h.required('type', 'credentials')
))
class PeerCreateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Creating peer entry'

    def describe(self, peer):
        return TaskDescription('Creating peer entry {name}', name=peer.get('name', ''))

    def verify(self, peer):
        if peer.get('type') not in self.dispatcher.call_sync('peer.peer_types'):
            raise VerifyException(errno.EINVAL, 'Unknown peer type {0}'.format(peer.get('type')))

        return ['system']

    def run(self, peer):
        self.join_subtasks(self.run_subtask('peer.{0}.create'.format(peer.get('type')), peer))


@description('Updates peer entry')
@accepts(str, h.ref('peer'))
class PeerUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updating peer entry'

    def describe(self, id, updated_fields):
        peer = self.datastore.get_by_id('peers', id)
        return TaskDescription('Updating peer entry {name}', name=peer.get('name', ''))

    def verify(self, id, updated_fields):
        return ['system']

    def run(self, id, updated_fields):
        peer = self.datastore.get_by_id('peers', id)
        if not peer:
            raise TaskException(errno.ENOENT, 'Peer {0} does not exist'.format(id))

        if 'type' in updated_fields and peer['type'] != updated_fields['type']:
            raise TaskException(errno.EINVAL, 'Peer type cannot be updated')

        self.join_subtasks(self.run_subtask('peer.{0}.update'.format(peer.get('type')), id, updated_fields))


@description('Deletes peer entry')
@accepts(str)
class PeerDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Deleting peer entry'

    def describe(self, id):
        peer = self.datastore.get_by_id('peers', id)
        return TaskDescription('Deleting peer entry {name}', name=peer.get('name', ''))

    def verify(self, id):
        return ['system']

    def run(self, id):
        if not self.datastore.exists('peers', ('id', '=', id)):
            raise TaskException(errno.EINVAL, 'Peer entry {0} does not exist'.format(id))

        peer = self.datastore.get_by_id('peers', id)

        self.join_subtasks(self.run_subtask('peer.{0}.delete'.format(peer.get('type')), id))


def _init(dispatcher, plugin):
    # Register schemas
    plugin.register_schema_definition('peer', {
        'type': 'object',
        'properties': {
            'name': {'type': 'string'},
            'id': {'type': 'string'},
            'type': {'type': 'string'},
            'credentials': {'$ref': 'peer-credentials'}
        },
        'additionalProperties': False
    })

    # Register providers
    plugin.register_provider('peer', PeerProvider)

    # Register credentials schema
    def update_peer_credentials_schema():
        plugin.register_schema_definition('peer-credentials', {
            'discriminator': 'type',
            'oneOf': [
                {'$ref': '{0}-credentials'.format(name)} for name in dispatcher.call_sync('peer.peer_types')
            ]
        })

    # Register event handlers
    dispatcher.register_event_handler('server.plugin.loaded', update_peer_credentials_schema)

    # Register tasks
    plugin.register_task_handler("peer.create", PeerCreateTask)
    plugin.register_task_handler("peer.update", PeerUpdateTask)
    plugin.register_task_handler("peer.delete", PeerDeleteTask)

    # Register event types
    plugin.register_event_type('peer.changed')

    # Init peer credentials schema
    update_peer_credentials_schema()
