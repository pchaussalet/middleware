#!/usr/local/bin/python3
#
# Copyright 2014-2016 iXsystems, Inc.
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
import logging
import socket
import argparse
import datastore
import time
import setproctitle
import select
import threading
import pybonjour
from datastore.config import ConfigStore
from freenas.dispatcher.client import Client, ClientError
from freenas.dispatcher.rpc import RpcService, RpcException
from freenas.utils import configure_logging
from freenas.utils.debug import DebugService


class ManagementService(RpcService):
    def __init__(self, ctx):
        self.context = ctx

    def die(self):
        pass


class DiscoveryService(RpcService):
    def __init__(self, context):
        self.context = context

    def find(self, regtype):
        services = []
        found = 0
        done = False
        cv = threading.Condition()

        def resolve_callback(sdref, flags, ifindex, error, fullname, hosttarget, port, txt_record):
            with cv:
                services.append({
                    'fullname': fullname,
                    'hosttarget': hosttarget,
                    'port': port
                })
                cv.notify()

        def browse_callback(sdref, flags, ifindex, error, service_name, regtype, reply_domain):
            nonlocal found, done

            if error != pybonjour.kDNSServiceErr_NoError or (not flags & pybonjour.kDNSServiceFlagsMoreComing):
                self.context.event_loop.unregister(sdref)
                with cv:
                    done = True
                    cv.notify()
                return

            self.context.event_loop.register(pybonjour.DNSServiceResolve(
                0, ifindex, service_name,
                regtype, reply_domain, resolve_callback
            ))

            with cv:
                found += 1
                cv.notify()

        sdref = pybonjour.DNSServiceBrowse(regtype=regtype, callBack=browse_callback)
        self.context.event_loop.register(sdref)
        with cv:
            cv.wait_for(lambda: done and found == len(services))
            return services


class EventLoop(object):
    def __init__(self):
        self.kq = select.kqueue()
        self.sdrefs = {}
        self.lock = threading.RLock()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def register(self, sd_ref, timeout=0):
        with self.lock:
            kev = select.kevent(sd_ref.fileno(), select.KQ_FILTER_READ, select.KQ_EV_ADD | select.KQ_EV_ENABLE)
            self.kq.control([kev], 0)
            self.sdrefs[sd_ref.fileno()] = (sd_ref, timeout)

    def unregister(self, sd_ref):
        with self.lock:
            kev = select.kevent(sd_ref.fileno(), select.KQ_FILTER_READ, select.KQ_EV_DELETE)
            self.kq.control([kev], 0)
            del self.sdrefs[sd_ref.fileno()]
            sd_ref.close()

    def run(self):
        while True:
            with self.lock:
                events = self.kq.control(None, 16, 1)
                for i in events:
                    if i.ident not in self.sdrefs:
                        continue

                    sdref, _ = self.sdrefs.get(i.ident)
                    if not sdref:
                        continue

                    pybonjour.DNSServiceProcessResult(sdref)


class Main(object):
    def __init__(self):
        self.logger = logging.getLogger('neighbord')
        self.config = None
        self.datastore = None
        self.configstore = None
        self.client = None
        self.logger = logging.getLogger()
        self.event_loop = EventLoop()

    def init_datastore(self):
        try:
            self.datastore = datastore.get_datastore()
        except datastore.DatastoreException as err:
            self.logger.error('Cannot initialize datastore: %s', str(err))
            sys.exit(1)

        self.configstore = ConfigStore(self.datastore)

    def init_dispatcher(self):
        def on_error(reason, **kwargs):
            if reason in (ClientError.CONNECTION_CLOSED, ClientError.LOGOUT):
                self.logger.warning('Connection to dispatcher lost')
                self.connect()

        self.client = Client()
        self.client.on_error(on_error)
        self.connect()

    def register_service(self, name, regtype, port):
        def callback(sdref, flags, error, name, regtype, domain):
            self.logger.info('Registered service {0} (regtype {1}, domain {2})'.format(
                name,
                regtype,
                domain
            ))

        sdref = pybonjour.DNSServiceRegister(name=name, regtype=regtype, port=port, callBack=callback)
        self.event_loop.register(sdref)

    def register(self):
        hostname = socket.gethostname()
        self.register_service(hostname, '_freenas._tcp.', 80)
        self.register_service(hostname, '_http._tcp.', 80)
        self.register_service(hostname, '_ssh._tcp.', 22)
        self.register_service(hostname, '_sftp-ssh._tcp.', 22)

    def connect(self):
        while True:
            try:
                self.client.connect('unix:')
                self.client.login_service('neighbord')
                self.client.enable_server()
                self.client.register_service('neighbord.management', ManagementService(self))
                self.client.register_service('neighbord.discovery', DiscoveryService(self))
                self.client.register_service('neighbord.debug', DebugService())
                self.client.resume_service('neighbord.management')
                self.client.resume_service('neighbord.discovery')
                self.client.resume_service('neighbord.debug')
                return
            except (OSError, RpcException) as err:
                self.logger.warning('Cannot connect to dispatcher: {0}, retrying in 1 second'.format(str(err)))
                time.sleep(1)

    def main(self):
        parser = argparse.ArgumentParser()
        args = parser.parse_args()
        configure_logging('/var/log/neighbord.log', 'DEBUG')

        setproctitle.setproctitle('neighbord')
        self.init_datastore()
        self.init_dispatcher()
        self.register()
        self.client.wait_forever()


if __name__ == '__main__':
    m = Main()
    m.main()

