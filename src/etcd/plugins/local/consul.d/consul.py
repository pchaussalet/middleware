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
import json
import socket
from datastore.config import ConfigNode


def run(context):
    node = ConfigNode('service.consul', context.configstore).__getstate__()
    config = {
        'bind_addr': node['bind_address'],
        'datacenter': node['datacenter'],
        'data_dir': '/var/tmp/consul',
        'node_name': node['node_name'] or socket.gethostname(),
        'server': node['server'],
        'rejoin_after_leave': True,
        'start_join': node['start_join'],
        'start_join_wan': node['start_join_wan']
    }

    os.makedirs('/usr/local/etc/consul.d', exist_ok=True)

    with open('/usr/local/etc/consul.d/consul.conf', 'w') as f:
        json.dump(config, f, indent=4)

    context.emit_event('etcd.file_generated', {
        'name': '/usr/local/etc/consul.d/consul.conf'
    })
