from base import Resource, SingleItemBase


class ApplyResource(Resource):
    name = 'apply'
    post = 'atask:update.apply'


class CheckResource(Resource):
    name = 'check'
    post = 'atask:update.check'


class CheckFetchResource(Resource):
    name = 'checkfetch'
    post = 'atask:update.checkfetch'


class DownloadResource(Resource):
    name = 'download'
    post = 'atask:update.download'


class UpdateNowResource(Resource):
    name = 'updatenow'
    post = 'atask:update.updatenow'


class VerifyResource(Resource):
    name = 'verify'
    post = 'atask:update.verify'


class UpdateSingleItem(SingleItemBase):
    namespace = 'update'
    subresources = (
        ApplyResource,
        CheckResource,
        CheckFetchResource,
        DownloadResource,
        UpdateNowResource,
        VerifyResource,
    )


def _init(rest):
    rest.register_singleitem(UpdateSingleItem)
