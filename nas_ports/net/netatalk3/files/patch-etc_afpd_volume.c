--- etc/afpd/volume.c.orig	2016-09-27 18:59:31.340571000 -0700
+++ etc/afpd/volume.c	2016-09-27 19:01:47.878600000 -0700
@@ -385,10 +385,10 @@
                         ashort |= VOLPBIT_ATTR_TM;
 #ifdef HAVE_LDAP
                     if (!ldap_config_valid || vol->v_flags & AFPVOL_NONETIDS)
-                        ashort |= VOLPBIT_ATTR_NONETIDS;
 #else
-                    ashort |= VOLPBIT_ATTR_NONETIDS;
+                    if (vol->v_flags & AFPVOL_NONETIDS)
 #endif
+                        ashort |= VOLPBIT_ATTR_NONETIDS;
                     if (obj->afp_version >= 32) {
                         if (vol->v_vfs_ea)
                             ashort |= VOLPBIT_ATTR_EXT_ATTRS;
