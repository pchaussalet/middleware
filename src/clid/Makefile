PREFIX ?= /usr/local
PYTHON ?= python

install:
	install etc/clid ${PREFIX}/etc/rc.d/
	install sbin/clid ${PREFIX}/sbin/
	install -d ${PREFIX}/lib/clid
	install -d ${PREFIX}/lib/clid/src
	cp -a src/ ${PREFIX}/lib/clid/src/
