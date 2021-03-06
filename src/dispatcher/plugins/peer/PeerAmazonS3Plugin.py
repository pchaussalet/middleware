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
from freenas.dispatcher.rpc import SchemaHelper as h, description, accepts, returns, private, generator
from task import Task, Provider, TaskException, VerifyException, query, TaskDescription
from freenas.utils import query as q


logger = logging.getLogger(__name__)


@description('Provides information about Amazon S3 peers')
class PeerAmazonS3Provider(Provider):
    @query('peer')
    @generator
    def query(self, filter=None, params=None):
        return q.query(
            self.dispatcher.call_sync('peer.query', [('type', '=', 'amazon-s3')]),
            *(filter or []),
            stream=True,
            **(params or {})
        )

    @private
    @accepts(str)
    @returns(h.ref('peer-status'))
    def get_status(self, id):
        return {'state': 'NOT_SUPPORTED', 'rtt': None}


@private
@description('Creates a Amazon S3 peer entry')
@accepts(h.all_of(
    h.ref('peer'),
    h.required('type', 'credentials')
))
class AmazonS3PeerCreateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Creating Amazon S3 peer entry'

    def describe(self, peer, initial_credentials):
        return TaskDescription('Creating Amazon S3 peer entry {name}', name=peer.get('name', ''))

    def verify(self, peer, initial_credentials):
        if peer.get('type') != 'amazon-s3':
            raise VerifyException(errno.EINVAL, 'Peer type must be selected as Amazon S3')

        return ['system']

    def run(self, peer, initial_credentials):
        if 'name' not in peer:
            raise TaskException(errno.EINVAL, 'Name has to be specified')

        if self.datastore.exists('peers', ('name', '=', peer['name'])):
            raise TaskException(errno.EINVAL, 'Peer entry {0} already exists'.format(peer['name']))

        return self.datastore.insert('peers', peer)


@private
@description('Updates a Amazon S3 peer entry')
@accepts(str, h.ref('peer'))
class AmazonS3PeerUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updating Amazon S3 peer entry'

    def describe(self, id, updated_fields):
        peer = self.datastore.get_by_id('peers', id)
        return TaskDescription('Updating Amazon S3 peer entry {name}', name=peer.get('name', ''))

    def verify(self, id, updated_fields):
        if 'type' in updated_fields:
            raise VerifyException(errno.EINVAL, 'Type of peer cannot be updated')

        return ['system']

    def run(self, id, updated_fields):
        peer = self.datastore.get_by_id('peers', id)
        if not peer:
            raise TaskException(errno.ENOENT, 'Peer {0} does not exist'.format(id))

        peer.update(updated_fields)
        if 'name' in updated_fields and self.datastore.exists('peers', ('name', '=', peer['name'])):
            raise TaskException(errno.EINVAL, 'Peer entry {0} already exists'.format(peer['name']))

        self.datastore.update('peers', id, peer)


@private
@description('Deletes Amazon S3 peer entry')
@accepts(str)
class AmazonS3PeerDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Deleting Amazon S3 peer entry'

    def describe(self, id):
        peer = self.datastore.get_by_id('peers', id)
        return TaskDescription('Deleting Amazon S3 peer entry {name}', name=peer.get('name', ''))

    def verify(self, id):
        return ['system']

    def run(self, id):
        if not self.datastore.exists('peers', ('id', '=', id)):
            raise TaskException(errno.EINVAL, 'Peer entry {0} does not exist'.format(id))

        self.datastore.delete('peers', id)


def _depends():
    return ['PeerPlugin']


def _metadata():
    return {
        'type': 'peering',
        'subtype': 'amazon-s3'
    }


def _init(dispatcher, plugin):
    # Register schemas
    plugin.register_schema_definition('amazon-s3-credentials', {
        'type': 'object',
        'properties': {
            '%type': {'enum': ['amazon-s3-credentials']},
            'access_key': {'type': 'string'},
            'secret_key': {'type': 'string'},
            'region': {'type': ['string', 'null']},
            'bucket': {'type': 'string'},
            'folder': {'type': ['string', 'null']}
        },
        'additionalProperties': False
    })

    # Register providers
    plugin.register_provider('peer.amazon-s3', PeerAmazonS3Provider)

    # Register tasks
    plugin.register_task_handler("peer.amazon-s3.create", AmazonS3PeerCreateTask)
    plugin.register_task_handler("peer.amazon-s3.delete", AmazonS3PeerDeleteTask)
    plugin.register_task_handler("peer.amazon-s3.update", AmazonS3PeerUpdateTask)

