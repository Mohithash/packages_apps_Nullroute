# Nullroute — file context fragment.
#
# APPEND to device/lineage/sepolicy/common/private/file_contexts.
# Order does not matter here: file_contexts matching is by regex specificity,
# not by file order.
#
# NOTE ON WHAT IS *NOT* LISTED
# ---------------------------
# /data/misc/nullroute itself has no entry, so it keeps the label it inherits
# from /data(/.*)? — system_data_file. That is deliberate. netd has to traverse
# that directory to reach index/, and giving the parent a nullroute_* label
# would force a `search` grant to netd on a type that is otherwise entirely
# app-private (nullroute_data_file). Leaving the parent generic keeps the
# netd-facing surface to exactly three types.
#
# The four subdirectories are created by init at post-fs-data with these labels;
# files created inside them inherit the directory's type, so no type_transition
# is needed for current.nrdx, control.bin, ring.bin or anything else.
#
# ⚠ An OTA that first introduces these types finds the directories already
# present and does NOT relabel them — mkdir only labels what it creates. That is
# why rom/init.nullroute.rc runs restorecon_recursive /data/misc/nullroute right
# after the mkdirs.

/data/misc/nullroute/`index'(/.*)?   u:object_r:nullroute_index_file:s0
/data/misc/nullroute/ctl(/.*)?     u:object_r:nullroute_ctl_file:s0
/data/misc/nullroute/log(/.*)?     u:object_r:nullroute_log_file:s0
/data/misc/nullroute/priv(/.*)?    u:object_r:nullroute_data_file:s0

/system_ext/bin/nullroute_seed     u:object_r:nullroute_seed_exec:s0
/system_ext/bin/nrctl              u:object_r:nrctl_exec:s0
