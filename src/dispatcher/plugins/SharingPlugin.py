#
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

import os
import errno
from dispatcher.rpc import description, accepts, returns, private
from dispatcher.rpc import SchemaHelper as h
from task import Task, TaskException, VerifyException, Provider, RpcException, query


class SharesProvider(Provider):
    @query('share')
    def query(self, filter=None, params=None):
        return self.datastore.query('shares', *(filter or []), **(params or {}))

    @description("Returns list of supported sharing providers")
    @returns(h.array(str))
    def supported_types(self):
        result = {}
        for p in list(self.dispatcher.plugins.values()):
            if p.metadata and p.metadata.get('type') == 'sharing':
                result[p.metadata['method']] = {
                    'subtype': p.metadata['subtype'],
                    'perm_type': p.metadata.get('perm_type')
                }

        return result

    @description("Returns list of clients connected to particular share")
    @accepts(str)
    @returns(h.array(h.ref('share-client')))
    def get_connected_clients(self, share_name):
        share = self.datastore.get_by_id('share', share_name)
        if not share:
            raise RpcException(errno.ENOENT, 'Share not found')

        return self.dispatcher.call_sync('share.{0}.get_connected_clients'.format(share['type']), share_name)

    @description("Get shares dependent on provided filesystem path")
    @accepts(str)
    @returns(h.array('share'))
    def get_dependencies(self, path):
        result = []
        for i in self.datastore.query('shares', ('enabled', '=', True)):
            if i['target_path'][0] != '/':
                # non-filesystem share
                continue

            if i['target_path'].startswith(path):
                result.append(i)

        return result

    @private
    def translate_path(self, share_id):
        root = self.dispatcher.call_sync('volume.get_volumes_root')
        share = self.datastore.get_by_id(share_id)

        if share['target_type'] == 'DATASET':
            return os.path.join(root, share['target_path'])

        if share['target_type'] in ('DIRECTORY', 'FILE'):
            return share['target_path']

        raise RpcException(errno.EINVAL, 'Invalid share target type {0}'.format(share['target_type']))


@description("Creates new share")
@accepts(h.all_of(
    h.ref('share'),
    h.required('id', 'type', 'target_type', 'target_path', 'properties')
))
class CreateShareTask(Task):
    def verify(self, share):
        if not self.dispatcher.call_sync('share.supported_types').get(share['type']):
            raise VerifyException(errno.ENXIO, 'Unknown sharing type {0}'.format(share['type']))

        if self.datastore.exists(
            'shares',
            ('type', '=', share['type']),
            ('name', '=', share['name'])
        ):
            raise VerifyException(errno.EEXIST, 'Share {0} of type {1} already exists'.format(
                share['name'],
                share['type']
            ))

        return ['system']

    def run(self, share):
        share_type = self.dispatcher.call_sync('share.supported_types').get(share['type'])

        if share['target_type'] == 'DATASET':
            dataset = share['target_path']
            pool = share['target_path'].split('/')[0]
            if not self.dispatcher.call_sync('zfs.dataset.query', [('name', '=', dataset)], {'single': True}):
                if share_type['subtype'] == 'file':
                    self.join_subtasks(self.run_subtask('volume.dataset.create', pool, dataset, 'FILESYSTEM', {
                        'permissions_type': share_type['perm_type'],
                    }))

                if share_type['subtype'] == 'block':
                    self.join_subtasks(self.run_subtask('volume.dataset.create', pool, dataset, 'VOLUME', {
                        'volsize': share['properties']['size'],
                    }))
            else:
                if share_type['subtype'] == 'file':
                    self.run_subtask('volume.dataset.update', pool, dataset, {
                        'permissions_type': share_type['perm_type']
                    })

        if share['target_type'] == 'DIRECTORY':
            # Verify that target directory exists
            if not os.path.isdir(share['target_path']):
                raise TaskException(errno.ENOENT, "Target directory {0} doesn't exist".format(share['target_path']))

        if share['target_type'] == 'FILE':
            # Verify that target file exists
            if not os.path.isfile(share['target_path']):
                raise TaskException(errno.ENOENT, "Target file {0} doesn't exist".format(share['target_path']))

        self.join_subtasks(self.run_subtask('share.{0}.create'.format(share['type']), share))
        self.dispatcher.dispatch_event('share.changed', {
            'operation': 'create',
            'ids': [share['id']]
        })


@description("Updates existing share")
@accepts(str, h.ref('share'))
class UpdateShareTask(Task):
    def verify(self, name, updated_fields):
        share = self.datastore.get_by_id('shares', name)
        if not share:
            raise VerifyException(errno.ENOENT, 'Share not found')

        return ['system']

    def run(self, name, updated_fields):
        share = self.datastore.get_by_id('shares', name)
        self.join_subtasks(
            self.run_subtask('share.{0}.update'.format(share['type']), name, updated_fields)
        )
        self.dispatcher.dispatch_event('share.changed', {
            'operation': 'update',
            'ids': [share['id']]
        })


@description("Deletes share")
@accepts(str)
class DeleteShareTask(Task):
    def verify(self, name):
        share = self.datastore.get_by_id('shares', name)
        if not share:
            raise VerifyException(errno.ENOENT, 'Share not found')

        return ['system']

    def run(self, name):
        share = self.datastore.get_by_id('shares', name)
        self.join_subtasks(self.run_subtask('share.{0}.delete'.format(share['type']), name))
        self.dispatcher.dispatch_event('share.changed', {
            'operation': 'delete',
            'ids': [name]
        })


@description("Deletes all shares dependent on specified volume/dataset")
@accepts(str)
class DeleteDependentShares(Task):
    def verify(self, path):
        return ['system']

    def run(self, path):
        subtasks = []
        ids = []
        for i in self.dispatcher.call_sync('share.get_dependencies', path):
            subtasks.append(self.run_subtask('share.delete', i['id']))
            ids.append(i['id'])

        self.join_subtasks(*subtasks)
        self.dispatcher.dispatch_event('share.changed', {
            'operation': 'delete',
            'ids': ids
        })


def _init(dispatcher, plugin):
    plugin.register_schema_definition('share', {
        'type': 'object',
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'description': {'type': 'string'},
            'enabled': {'type': 'boolean'},
            'type': {'type': 'string'},
            'target_type': {
                'type': 'string',
                'enum': ['DATASET', 'DIRECTORY', 'FILE']
            },
            'target_path': {'type': 'string'},
            'properties': {'type': 'object'}
        }
    })

    plugin.register_schema_definition('share-client', {
        'type': 'object',
        'properties': {
            'host': {'type': 'string'},
            'share': {'type': 'string'},
            'user': {'type': ['string', 'null']},
            'connected_at': {'type': ['string', 'null']},
            'extra': {
                'type': 'object'
            }
        }
    })

    dispatcher.require_collection('share', 'string')
    plugin.register_provider('share', SharesProvider)
    plugin.register_task_handler('share.create', CreateShareTask)
    plugin.register_task_handler('share.update', UpdateShareTask)
    plugin.register_task_handler('share.delete', DeleteShareTask)
    plugin.register_task_handler('share.delete_dependent', DeleteDependentShares)
    plugin.register_event_type('share.changed')
