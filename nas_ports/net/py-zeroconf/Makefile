# $FreeBSD$

PORTNAME=	zeroconf
PORTVERSION=	0.17.6
CATEGORIES=	devel python
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}

RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}six>1.3.0:${PORTSDIR}/devel/py-six \
		${PYTHON_PKGNAMEPREFIX}netifaces>0:${PORTSDIR}/net/py-netifaces

MAINTAINER=	jceel@FreeBSD.org
COMMENT=	Pure Python Multicast DNS Service Discovery Library (Bonjour/Avahi compatible)

USES=		python
USE_PYTHON=	autoplist distutils
USE_GITHUB=	yes
GH_ACCOUNT=	jstasiak
GH_PROJECT=	python-zeroconf
GH_TAG=		0.17.6

.include <bsd.port.mk>
