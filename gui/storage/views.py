#+
# Copyright 2010 iXsystems
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
# $FreeBSD$
#####################################################################
from freenasUI.storage.forms import * 
from freenasUI.storage.models import * 
from freenasUI.services.models import services, CIFS, AFP, NFS 
from freenasUI.services.forms import CIFSForm, AFPForm, NFSForm 
from django.forms.models import modelformset_factory
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.decorators import login_required
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.contrib.auth import authenticate, login, logout
from django.template import RequestContext
from django.http import Http404
from django.views.generic.list_detail import object_detail, object_list
from django.views.generic.create_update import update_object, delete_object
from freenasUI.middleware.notifier import notifier
from django.core import serializers
import os, commands

## Disk section

@login_required
def storage(request):
    mp_list = MountPoint.objects.select_related().all()
    variables = RequestContext(request, {
        'focused_tab' : 'storage',
        'mp_list': mp_list,
    })
    return render_to_response('storage/index.html', variables)

@login_required
def volume_disks(request, volume_id):
    # mp = MountPoint.objects.get(mp_volume = volume_id)
    volume = Volume.objects.get(id = volume_id)
    disk_list = Disk.objects.filter(disk_group__group_volume = volume_id)
    variables = RequestContext(request, {
        'focused_tab' : 'storage',
        'volume': volume,
        'disk_list': disk_list,
    })
    return render_to_response('storage/volume_detail.html', variables)

@login_required
def diskgroup_add_wrapper(request, *args, **kwargs):
    wiz = DiskGroupWizard([DiskGroupForm])
    return wiz(request, *args, **kwargs)

@login_required
def diskgroup_list(request, template_name='freenas/disks/groups/diskgroup_list.html'):
    query_set = DiskGroup.objects.values().order_by('name')
    return object_list(
        request,
        template_name = template_name,
        queryset = query_set
    )


@login_required
def volume_create_wrapper(request, *args, **kwargs):
    wiz = VolumeWizard([VolumeForm])
    return wiz(request, *args, **kwargs)

@login_required
def volume_list(request, template_name='freenas/disks/volumes/volume_list.html'):
    query_set = Volume.objects.values().order_by('groups')
    #if len(query_set) == 0:
    #    raise Http404()
    return object_list(
        request,
        template_name = template_name,
        queryset = query_set
    )

@login_required
def dataset_create(request):
    mp_list = MountPoint.objects.select_related().all()
    defaults = { 'dataset_compression' : 'inherit', 'dataset_atime' : 'inherit', }
    dataset_form = ZFSDataset_CreateForm(initial=defaults)
    if request.method == 'POST':
        dataset_form = ZFSDataset_CreateForm(request.POST)
        if dataset_form.is_valid():
            props = {}
            cleaned_data = dataset_form.cleaned_data
            volume = Volume.objects.get(id=cleaned_data.get('dataset_volid'))
            volume_name = volume.vol_name
            dataset_name = "%s/%s" % (volume_name, cleaned_data.get('dataset_name'))
            dataset_compression = cleaned_data.get('dataset_compression')
            if dataset_compression != 'inherit':
                props['compression']=dataset_compression
            dataset_atime = cleaned_data.get('dataset_atime')
            if dataset_atime != 'inherit':
                props['atime']=dataset_atime
            notifier().create_zfs_dataset(path=dataset_name.__str__(), props=props)
            mp = MountPoint(mp_volume=volume, mp_path='/mnt/%s' % (dataset_name), mp_options='noauto', mp_ischild=True)
            mp.save()
            return HttpResponseRedirect('/storage/')
    variables = RequestContext(request, {
        'focused_tab' : 'storage',
        'mp_list': mp_list,
        'form': dataset_form
    })
    return render_to_response('storage/datasets.html', variables)

@login_required
def mp_permission(request, object_id):
    mp = MountPoint.objects.get(id = object_id)
    mp_list = MountPoint.objects.select_related().all()
    if request.method == 'POST':
        form = MountPointAccessForm(request.POST)
        if form.is_valid():
            mp_path=mp.mp_path.__str__()
            form.commit(path=mp_path)
            return HttpResponseRedirect('/storage/')
    else:
        form = MountPointAccessForm()
    variables = RequestContext(request, {
        'focused_tab' : 'storage',
        'mp': mp,
        'mp_list': mp_list,
        'form': form,
    })
    return render_to_response('storage/permission.html', variables)

@login_required
def dataset_delete(request, object_id):
    obj = MountPoint.objects.get(id=object_id)
    if request.method == 'POST':
        notifier().destroy_zfs_dataset(path = obj.mp_path[5:].__str__())
        obj.delete()
        return HttpResponseRedirect('/storage/')
    else:
        c = RequestContext(request, {
            'focused_tab' : 'storage',
            'object': obj,
        })
        return render_to_response('storage/dataset_confirm_delete.html', c)

@login_required
def generic_detail(request, object_id, model_name):
    storage_name_model_map = {
        'disk':		Disk,
        'diskgroup':	DiskGroup,
        'volume':	Volume,
    }
    model = storage_name_model_map[model_name]
    return object_detail(request, queryset=model.objects.all(), object_id=object_id)

@login_required
def generic_delete(request, object_id, model_name):
	storage_name_model_map = {
		'disk':	Disk,
		'group':	DiskGroup,
		'volume':	Volume,
	}
        # TODO: Extend delete_object to add a callback to do this
        # TODO: Recursively delete file extents as well
        if request.method == 'POST' and model_name == 'volumes':
            vol = Volume.objects.get(id = object_id)
            if vol.vol_fstype == 'iscsi':
                from freenasUI.services.models import *
                diskdev = u'/dev/' + vol.vol_name[6:]
                ist = iSCSITargetExtent.objects.get(iscsi_target_extent_path = diskdev)
                ist.delete()
	return delete_object(
		request = request,
		model = storage_name_model_map[model_name],
		post_delete_redirect = '/storage/',
		object_id = object_id, )

@login_required
def generic_update(request, object_id, model_name):
        model_name_to_model_and_form_map = {
		'disk':	( Disk, DiskFormPartial ),
	}
	model, form_class = model_name_to_model_and_form_map[model_name]
	return update_object(
		request = request,
		model = model, form_class = form_class,
		post_save_redirect = '/storage/',
		object_id = object_id, )
