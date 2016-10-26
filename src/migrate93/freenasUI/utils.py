# Copyright 2010-2016 iXsystems, Inc.
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


def ensure_unique(datastore, ds_tuple, orm_handle, orm_tuple, **kwargs):
    """
    Helper function to facilitate strict checking of whether any
    database entry in the 9.x database is not already present in the
    10 datastore. If it does find any match at all then it will throw
    a ValueError with the specifics as to why
    Values that one can specify:
        datastore: 10 intialized orm_handle
        ds_tuple: (10_collection_name, primary_key) (mandatory)
        orm_handle: 9.x orm handle (mandatory)
        orm_tuple: (9.x app name, primary_key)
        orm_filter: Optional filter for the 9.x orm query
    """
    orm_filter = kwargs.get('orm_filter', None)
    old_ids = [obj[orm_tuple[1]] for obj in orm_handle[orm_tuple[0]].objects.filter(orm_filter)]
    conflicting_ids = datastore.query(ds_tuple[0], (ds_tuple[1], 'in', old_ids))
    if conflicting_ids:
        raise ValueError(
            "For the collection: {0} (9.x app name: {1})".format(ds_tuple[0])
            "These objects were found in the 9.x database but pre-existed in the 10 datastore"
            "{0}".format(list(conflicting_ids))
        )

