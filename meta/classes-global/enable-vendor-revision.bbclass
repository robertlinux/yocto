#
# Copyright (C) 2024 Wind River Systems, Inc
#
# SPDX-License-Identifier: GPL-2.0-only
#

# This bbclass is used for appending VENDOR_REVISION to PR from
# vendor-revision.conf for the recipes which have patches.
# To enable it:
# 1. Generate vendor-revision.conf with gen-vendor-revision.bbclass
# 2. Remove 'gen-vendor-revision' from conf/local.conf if it is there
# 3. Add the following lines to conf/local.conf
# require /path/to/vendor-revision.conf
# INHERIT += "enable-vendor-revision"
#
# The vendor-revision.conf is not a must, but without it, all the recipes which
# patches will have a VR, there is no different in the first release such as
# Yocto 5.1, but all the VRs will be updated from "vr51" to "vr511" in Yocto
# 5.1.1 since there is no history data (vendor-revision.conf).
#
# The VENDOR_REVISION_PREFIX is used for:
# - Avoid confusions with PR Server
# - Customize for your own distro
VENDOR_REVISION_PREFIX ??= ".vr"

def get_src_patches(d):
    import oe.patch
    local_patches = set()
    bb.fetch.get_hashvalue(d)
    for patch in oe.patch.src_patches(d):
        _, _, local, _, _, parm = bb.fetch.decodeurl(patch)
        local_patches.add(local)
    return local_patches

def is_work_shared(d):
    sharedworkdir = os.path.join(d.getVar('TMPDIR'), 'work-shared')
    return d.getVar('S').startswith(sharedworkdir)

def vr_need_skip(d):

    if is_work_shared(d):
        return False

    packages = d.getVar('PACKAGES')
    if (not packages) or bb.data.inherits_class('nopackages', d) or \
             bb.data.inherits_class('nativesdk', d):
        return True

    # Skip VR when no patches
    if get_src_patches(d):
        return False
    else:
        return True

def get_var_short(var):
    return '/'.join(var.split('/')[-4:]).replace('/', '_')

def get_file_short(d):
    return get_var_short(d.getVar('FILE'))

# Allow users to customize the VR format since different Distro may have
# different DISTRO_VERSIONs
GET_CURRENT_VENDOR_REVISION ??= "get_current_vendor_revision(d)"

def get_current_vendor_revision(d):
    distro_version = d.getVar('DISTRO_VERSION')
    vendor_revision = distro_version.replace('.', '')

    vr_prefix = d.getVar('VENDOR_REVISION_PREFIX') or ''
    if vr_prefix:
        vendor_revision = vr_prefix + vendor_revision

    vr_suffix = d.getVar('VENDOR_REVISION_SUFFIX') or ''
    if vr_suffix:
        vendor_revision += vr_suffix

    return vendor_revision

python() {
    """
    Set PR:append = "VENDOR_REVISION" for the recipes
    """

    # Skip when gen-vendor-revision is inherited
    if bb.data.inherits_class('gen-vendor-revision', d):
        bb.debug(1, 'Skipping enabling VR for %s since gen-vendor-revision is inherited' % d.getVar('PN'))
        return

    if vr_need_skip(d):
        return

    # Directly use VENDOR_REVISION if the recipe sets it.
    vr = d.getVar('VENDOR_REVISION')
    if not vr:
        file_short = get_file_short(d)
        val = d.getVarFlag('VENDOR_REVISION', file_short)
        if val:
            # The first item is VENDOR_REVISION
            vr = val.split()[0]
            # The d.getVarFlag("VENDOR_REVISION", "tmp_work-shared_qemux86-64_kernel-source")
            # return None when kernel doesn't have patches, and vr_need_skip()
            # can't skip work-shared recipes. The None is a string here.
            if vr == 'None':
                return

    if not vr:
        # It's a new recipe, defult to current VR
        vr = eval(d.getVar('GET_CURRENT_VENDOR_REVISION'))

    bb.debug(1, 'Appending VENDOR_REVISION %s to PR' % vr)
    d.appendVar('PR', vr)
}

GLOBAL_VENDOR_REVISION_WARN ??= '1'
addhandler warn_for_global_vr
warn_for_global_vr[eventmask] = "bb.event.ConfigParsed"
python warn_for_global_vr() {
    # The VENDOR_REVISION should be set via recipe level, otherwise, there
    # might be PR bombs or no effect, so warn for global VENDOR_REVISION
    global_vr = d.getVar('VENDOR_REVISION')
    if global_vr and bb.utils.to_boolean(d.getVar('GLOBAL_VENDOR_REVISION_WARN')):
        bb.warn('The global VENDOR_REVISION (%s) may cause unneeded packages upgrading,' % global_vr)
        bb.warn('or make VENDOR_REVISION invalid.')
        bb.warn('The above warning can be disabled by GLOBAL_VENDOR_REVISION_WARN = "0"\n')
}
