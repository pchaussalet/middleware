#
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

import select
import logging
import threading
import pybonjour
from plugin import NeighborDiscoveryPlugin


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


class MDNSDiscoveryPlugin(NeighborDiscoveryPlugin):
    def __init__(self, context):
        super(MDNSDiscoveryPlugin, self).__init__(context)
        self.event_loop = EventLoop()
        self.logger = logging.getLogger(self.__class__.__name__)

    def find(self, type):
        services = []
        found = 0
        done = False
        cv = threading.Condition()
        regtype = '_{0}._tcp'.format(type)

        def resolve_callback(sdref, flags, ifindex, error, fullname, hosttarget, port, txt_record):
            with cv:
                txt = pybonjour.TXTRecord.parse(txt_record)
                services.append({
                    'fullname': fullname,
                    'hostname': hosttarget,
                    'port': port,
                    'properties': {n: txt[n] for n in txt}
                })
                cv.notify()

        def browse_callback(sdref, flags, ifindex, error, service_name, regtype, reply_domain):
            nonlocal found, done

            if error != pybonjour.kDNSServiceErr_NoError or (not flags & pybonjour.kDNSServiceFlagsMoreComing):
                self.event_loop.unregister(sdref)
                with cv:
                    done = True
                    cv.notify()
                return

            self.event_loop.register(pybonjour.DNSServiceResolve(
                0, ifindex, service_name,
                regtype, reply_domain, resolve_callback
            ))

            with cv:
                found += 1
                cv.notify()

        sdref = pybonjour.DNSServiceBrowse(regtype=regtype, callBack=browse_callback)
        self.event_loop.register(sdref)
        with cv:
            cv.wait_for(lambda: done and found == len(services))
            return services

    def register(self, type, name, port, properties=None):
        def callback(sdref, flags, error, name, regtype, domain):
            self.logger.info('Registered service {0} (regtype {1}, domain {2})'.format(
                name,
                regtype,
                domain
            ))

        regtype = '_{0}._tcp'.format(type)
        txt = pybonjour.TXTRecord(items=(properties or {}))
        sdref = pybonjour.DNSServiceRegister(name=name, regtype=regtype, port=port, callBack=callback, txtRecord=txt)
        self.event_loop.register(sdref)

    def unregister(self, type, name, port):
        pass


def _init(context):
    context.register_plugin('mdns', MDNSDiscoveryPlugin)
