#
# Copyright (C) 2024 Wind River Systems, Inc
#
# SPDX-License-Identifier: GPL-2.0-only
#

# The VENDOR_REVISION is for cve scanners to know the CVEs have been fixed in a
# lower version, CVE scanners such as Trivy can know the CVEs have been fixed
# in a higher version, but it can't know the CVE is fixed in a lower version without
# a helper, we have the following ways to set the helper:
# 1) Use PR server
#    This doesn't work since the server updates PR for any changes.
#
# 2) Update PR manually when add a CVE patch
#    This is doesn't work either since:
#    - This is very trivial and people may forget to update the PR
#    - The PR may be updated for other reasons except CVE patches
#
# So we need a specific part such as VENDOR_REVISION for cve scanners.
# The VENDOR_REVISION is designed as part of PR:
#   PR:append = ".vr51"
# - ".vr51": The VENDOR_REVISION
# - "vr": Vendor Revision, can be set to other values such as oe or poky
# - "51": Convert from DISTRO_VERSION (Yocto 5.1), it can be customized with
#         a function defined in GET_CURRENT_VENDOR_REVISION.
# - The VENDOR_REVISION will only append to the recipes which have patches
#
# The initial VENDOR_REVISION is '51', and will be updated when both of the
# following 2 conditions are met:
# - The DISTRO VERSION is updated, for example, from 5.1 to 5.1.1
# - The recipe's patches are changed (Patches added, removed or updated),
#   otherwise, it will still be "51" when Yocto updated to 5.1.1, this can avoid
#   unnecessary PR bump.
#
# The VENDOR_REVISION can be set in each recipe, but that is very trivial, this
# bbclass is trying collect as much recipe's patches as possible and put all of
# them in one file, and simulate set VENDOR_REVISION in the recipes, it is like:
#
# VENDOR_REVISION[meta_recipes-support_libssh2_libssh2_1.11.0.bb] ??= '${VENDOR_REVISION_PREFIX}51 \
#    CVE-2023-48795:CVE-2023-48795.patch:b6c68cd1f0631180914ff112ac0c29c4 \
#    notcve:0001-disable-DSA-by-default.patch:61b6368d4a969d187805393d8b8fee85'
#
#  - Use path_to_recipe.bb (Not PN or BPN) as the key is mainly because there
#    might be multiple versions for a recipe, PN or BPN can't distinguish that,
#    use recipe.bb as the key can simulate set VENDOR_REVISION in the recipes better.
#  - Track Non-CVE patches (notcve) is because:
#    The Non-CVE patch itself doesn't fix a CVE, but it may introduce CVEs, for example,
#    a) There is a hello_1.0.bb which has no CVE issues in Yocto 5.1,
#    b) A Non-CVE patch is applied to hello_1.0.bb and introduces a CVE issue
#       in Yocto 5.1.1, then the cve scanners can't know whether hello-1.0.rpm in
#       Yocto 5.1 is affected by the CVE or not, so we need track all the patches.
#  - The VENDOR_REVISION can be set manually in the recipe or in
#    vendor-revision-manual.inc if this bbclass can't handle it correctly.
#
# Examples for rpm packages with VR:
# - Without PR Server: openssl-3.3.1-r0.vr51.core2_64.rpm
# - With PR Server: openssl-3.3.1-r0.vr51.0.core2_64.rpm
# - No patches: base-files-3.0.14-r0.qemux86_64.rpm
#
# This bbclass is used for generating VENDOR_REVISION for each recipe,
# it can't be used for common building.
#
# Add the following line to conf/local.conf to enable it:
# INHERIT += "gen-vendor-revision"
#
# Run the following command to generate VR for all recipes
# $ bitbake -p
#
# The result will be in the file set by ${VENDOR_REVISION_ALL}, for example,
# tmp/vendor-revisions/qemux86-64/vendor-revision.conf
#
# Check enable-vendor-revision.bbclass on how to enable VENDOR_REVISION for the
# build.

inherit enable-vendor-revision

VENDOR_REVISION_DIR ?= "${TMPDIR}/vendor-revisions/${MACHINE}"
VENDOR_REVISION_ALL ?= "${VENDOR_REVISION_DIR}/vendor-revision.conf"

# For extra customization on a released version, for example, users
# may have local patches on 5.0.1.
#VENDOR_REVISION_SUFFIX = ".custom1"

# Do not skip libgfortran
FORTRAN:forcevariable = ",fortran"

# Skip feature check
PARSE_ALL_RECIPES = "1"

# Extra OVERRIDES
GEN_VENDOR_REVISION_OVERRIDES ??= ""

addhandler gen_vr_fatal
gen_vr_fatal[eventmask] = "bb.event.BuildStarted"
python gen_vr_fatal() {
    bb.fatal('Only bitbake -p is supported when gen-vendor-revision.bbclass is enabled!')
}

addhandler gen_vr_prepare
gen_vr_prepare[eventmask] = "bb.event.CacheLoadStarted"
python gen_vr_prepare() {
    vendor_revision_dir = d.getVar('VENDOR_REVISION_DIR')
    # Need a fresh VENDOR_REVISION_DIR and CACHE dir
    for k in ('VENDOR_REVISION_DIR', 'CACHE'):
        value = d.getVar(k)
        bb.note("Removing %s" % value)
        bb.utils.remove(value, True)
        bb.utils.mkdirhier(value)
}

# Generate VENDOR_REVISION for each recipe
addhandler gen_vr_recipe_handler
gen_vr_recipe_handler[eventmask] = "bb.event.RecipeParsed"
python gen_vr_recipe_handler() {
    """
    Generate VENDOR_REVISION for each recipe, the format is:
    VENDOR_REVISION[recipe_file] ?= 'vr cveid1:patch1 notcve:patch2'
    """

    import hashlib

    if vr_need_skip(d):
        return

    def get_cve_patch(patch):
        ret = []
        patch_bn = os.path.basename(patch)
        # Open in 'text' mode doesn't work for very a few patches such as:
        # hddtemp_0.3-beta15-52.diff: 'utf-8' codec can't decode byte 0xe8 in
        # position 3851: invalid continuation byte
        with open(patch, 'rb') as f:
            # Get md5
            md5 = hashlib.md5()
            md5.update(f.read())
            hash = md5.hexdigest()
            patch_bn += ':%s' % md5.hexdigest()
            # Reset file postion
            f.seek(0, 0)
            for line in f:
                if not 'CVE:' in str(line):
                    continue
                line = line.decode('utf-8')
                if line.startswith('CVE:') and 'CVE-' in line:
                    line_split = line.split('CVE:')
                    for cveid in line_split[1].split():
                        cveid = cveid.strip()
                        if cveid.startswith('CVE-'):
                            ret.append('%s:%s' % (cveid, patch_bn))
        if not ret:
            ret.append('notcve:%s' % patch_bn)
        return ret

    def update_vr(patches):
        """
        Check whether recipe's VENDOR_REVISION need update or not
        * If old_vr == new_vf
          - No check is needed since they are in the same
            release, just update it.

        * If old_vr != new_vr:
          - If the patches are the same:
            Nothing changed, use the old_vr to avoid unneeded updates by dnf.

          - If the patches are different:
            Update to the new_vr
        """

        patches.sort()
        new_patches = ' '.join(patches)

        file_short = get_file_short(d)
        vr = eval(d.getVar('GET_CURRENT_VENDOR_REVISION'))
        old_val = d.getVarFlag('VENDOR_REVISION', file_short)

        # No checking is needed in the following cases:
        # - No old_val: It's a new vr, just update it
        if old_val:
            old_vr = old_val.split()[0]
            if old_vr:
                # In different releases, check whether need update
                if old_vr != vr:
                    old_patches = ' '.join(old_val.split()[1:])
                    # The patches are the same, no update is needed
                    if old_patches == new_patches:
                        vr = old_vr

        # Replace .vr -> ${VENDOR_REVISION_PREFIX}
        vr_prefix = d.getVar("VENDOR_REVISION_PREFIX") or ""
        vr = vr.removeprefix(vr_prefix)
        vr = '${VENDOR_REVISION_PREFIX}%s' % vr
        out_lines = []
        val = ""
        if new_patches:
            val = '%s %s' % (vr, new_patches)
            out_lines.append("VENDOR_REVISION[%s] ??= '%s'" % (file_short, val))

        if is_work_shared(d):
            s_short = get_var_short(d.getVar('S'))
            if val:
                out_lines.append("VENDOR_REVISION[%s] ?= '%s'" % (s_short, val))
            else:
                out_lines.append("VENDOR_REVISION[%s] ??= '${@d.getVarFlag(\"VENDOR_REVISION\", \"%s\")}'" \
                    % (file_short, s_short))
        if out_lines:
            out_file = os.path.join(d.getVar('VENDOR_REVISION_DIR'), file_short)
            with open(out_file, 'w') as f:
                f.write('%s\n' % '\n'.join(out_lines))

    patches = []
    localdata = bb.data.createCopy(d)
    localdata.setVar('OVERRIDES', localdata.getVar('OVERRIDES') + localdata.getVar('GEN_VENDOR_REVISION_OVERRIDES'))
    for local in get_src_patches(localdata):
        patches += get_cve_patch(local)
    update_vr(patches)
}

# Generate vendor-revision.conf
addhandler gen_vr_all_handler
gen_vr_all_handler[eventmask] = "bb.event.ParseCompleted"
python gen_vr_all_handler () {
    """
    Collect each recipe's vendor revision in VENDOR_REVISION_DIR and save
    to VENDOR_REVISION_ALL
    """
    import glob
    vendor_revision_dir = d.getVar('VENDOR_REVISION_DIR')
    patches = []
    output = d.getVar('VENDOR_REVISION_ALL')
    output_dir = os.path.dirname(output)
    for recipe in glob.glob(os.path.join(vendor_revision_dir, '*')):
        with open(recipe) as f:
            for line in f:
                if not line in (patches):
                    patches.append(line)
    patches.sort()
    with open(output, 'w') as f:
        f.write('include %s\n\n' % "vendor-revision-manual.inc")
        f.write(''.join(patches))
    bb.note('The recipes with patches are saved to %s' % output)
}

# Clear the base.bbclass magic srcrev call
fetcher_hashes_dummyfunc[vardepvalue] = ""
