# $FreeBSD$

PORTNAME=	dropbox
PORTVERSION=	v6.8.0
CATEGORIES=	net python
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}

MAINTAINER=	dev@ixsystems.com
COMMENT=	fficial Dropbox API Client

RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}typing>=3.5.2:devel/py-typing \
		${PYTHON_PKGNAMEPREFIX}six>=1.3.0:devel/py-six \
		${PYTHON_PKGNAMEPREFIX}requests>=2.5.1:www/py-requests

USES=		python
USE_PYTHON=	autoplist distutils
USE_GITHUB=	yes
GH_ACCOUNT=	dropbox
GH_PROJECT=	dropbox-sdk-python
GH_TAG=		v6.8.0

NO_ARCH=	yes

.include <bsd.port.mk>
