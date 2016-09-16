# $FreeBSD$

PORTNAME=	freenas-neighbord
PORTVERSION=	${PRODUCT_VERSION:C/\-.*//:C/\_.*//}
PORTREVISION=	${REVISION}

CATEGORIES=	freenas
VALID_CATEGORIES+= freenas

MAINTAINER=	dev@ixsystems.com
COMMENT=	FreeNAS neighbor discovery daemon

RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}consul>0:${PORTSDIR}/devel/py-consul \
		${PYTHON_PKGNAMEPREFIX}bonjour>0:${PORTSDIR}/dns/py-bonjour \
		${PYTHON_PKGNAMEPREFIX}freenas.utils>0:${PORTSDIR}/freenas/py-freenas.utils \
		${PYTHON_PKGNAMEPREFIX}freenas.dispatcher>0:${PORTSDIR}/freenas/py-freenas.dispatcher \

USES=		python
USE_PYTHON=	py3kplist
EXTRACT_ONLY=

NO_BUILD=	yes
MAKE_JOBS_UNSAFE= yes
ALL_TARGET=	obj all
WRKSRC=		/usr/middleware_src/neighbord

checksum fetch:
	${ECHO_CMD} ${.TARGET} not needed because building direct

do-install:
	${MAKE} -C ${WRKSRC} install PREFIX=${STAGEDIR}${PREFIX} PYTHON=${PYTHON_CMD}

post-install:
	${PYTHON_CMD} -m compileall ${STAGEDIR}${PREFIX}/lib/neighbord
	(cd ${STAGEDIR}${PREFIX}/lib/neighbord; ${FIND} -E . -type f -regex ".*.pyc?" \
		| ${SED} -e 's,^\./,,g' \
		| ${AWK} '{print length, $$0}' | ${SORT} -rn \
		| ${AWK} '{print "lib/neighbord/"$$2 }' >> ${TMPPLIST})

	(cd ${STAGEDIR}${PREFIX}/lib/neighbord/plugins; ${FIND} . -type f -regex ".*.pyc?" \
		| ${SED} -e 's,^\./,,g' \
		| ${AWK} '{print length, $$0}' | ${SORT} -rn \
		| ${AWK} '{print "lib/neighbord/plugins/"$$2 }' >> ${TMPPLIST})

.include <bsd.port.mk>
