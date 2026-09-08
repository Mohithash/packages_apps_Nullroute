# Nullroute — property context fragment.
#
# APPEND to device/lineage/sepolicy/common/private/property_contexts.
#
# Both entries end in a dot, which makes them prefix matches.
#
#   persist.sys.nullroute.mode         0 ENFORCE | 1 PAUSED | 2 OFF.
#                                      THE on-disk source of truth for
#                                      pause/enforce; NrControl::mode is derived
#                                      from it by the syncprop trigger. One
#                                      authority, so two switches can never
#                                      disagree.
#   persist.sys.nullroute.kill         1 = app-independent kill switch. The
#                                      resolver returns PASS for everything and
#                                      H4 stops skipping the L0 hosts scan. This
#                                      is the recovery path when the app cannot
#                                      be launched at all.
#   persist.sys.nullroute.fail_streak  boot-loop breaker counter (F7). Armed by
#                                      nullroute_seed at every post-fs-data,
#                                      cleared by the app after 120 s of healthy
#                                      uptime, quarantines the index at 3.
#   persist.sys.nullroute.deep         Deep mode (Phase 4) enable.
#
#   sys.nullroute.filter               written by netd at every state change:
#                                      ok:<gen> | nomap:<errno> | badhdr:<field>
#                                      | killed | off. Health signal #2 of
#                                      three, and the only one that is
#                                      independent of both the control page and
#                                      the app being alive (F8).
#   sys.nullroute.seed                 written by nullroute_seed: ok |
#                                      recompiled | quarantined:<reason> |
#                                      failed:<errno>.
#
# ro.nullroute.enabled is intentionally NOT listed. It is a build-time property
# shipped from rom/nullroute.mk and it falls through to default_prop, which is
# world-readable — correct for a static feature flag that vendor code may want
# to read, and it must not be system_restricted_prop or init could not publish
# it from build.prop in a context every reader can see.

persist.sys.nullroute.    u:object_r:nullroute_prop:s0
sys.nullroute.            u:object_r:nullroute_state_prop:s0
