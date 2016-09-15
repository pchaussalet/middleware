PREFIX ?= /usr/local
PYTHON ?= python

install:
	install etc/neighbord ${PREFIX}/etc/rc.d/
	install sbin/neighbord ${PREFIX}/sbin/
	install -d ${PREFIX}/lib/neighbord
	install -d ${PREFIX}/lib/neighbord/src
	cp -a src/ ${PREFIX}/lib/neighbord/src/
