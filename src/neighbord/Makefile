PREFIX ?= /usr/local
PYTHON ?= python

install:
	install etc/neighbord ${PREFIX}/etc/rc.d/
	install sbin/neighbord ${PREFIX}/sbin/
	install -d ${PREFIX}/lib/neighbord
	install -d ${PREFIX}/lib/neighbord/src
	install -d ${PREFIX}/lib/neighbord/plugins
	cp -a src/ ${PREFIX}/lib/neighbord/src/
	cp -a plugins/ ${PREFIX}/lib/neighbord/plugins/
