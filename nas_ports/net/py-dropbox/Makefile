# $FreeBSD$

PORTNAME=	dropbox
PORTVERSION=	6.8.0
CATEGORIES=	net python
MASTER_SITES=	CHEESESHOP
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}

MAINTAINER=	dev@ixsystems.com
COMMENT=	fficial Dropbox API Client

RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}typing>=3.5.2:devel/py-typing \
		${PYTHON_PKGNAMEPREFIX}six>=1.3.0:devel/py-six \
		${PYTHON_PKGNAMEPREFIX}requests>=2.5.1:www/py-requests

USES=		python
USE_PYTHON=	autoplist distutils

NO_ARCH=	yes

.include <bsd.port.mk>
