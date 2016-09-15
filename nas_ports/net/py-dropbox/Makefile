# $FreeBSD$

PORTNAME=	dropbox
PORTVERSION=	6.8.0
CATEGORIES=	net python
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}
DISTVERSIONPREFIX=	v

MAINTAINER=	dev@ixsystems.com
COMMENT=	Official Dropbox API Client

RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}typing>=3.5.2:devel/py-typing \
		${PYTHON_PKGNAMEPREFIX}six>=1.3.0:devel/py-six \
		${PYTHON_PKGNAMEPREFIX}requests>=2.5.1:www/py-requests

USES=		python
USE_PYTHON=	autoplist distutils
USE_GITHUB=	yes
GH_ACCOUNT=	dropbox
GH_PROJECT=	dropbox-sdk-python

NO_ARCH=	yes

.include <bsd.port.mk>
