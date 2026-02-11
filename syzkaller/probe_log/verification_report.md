# PROBE Verification Report
**Period**: 2026-02-12 02:16 ~ 06:00 KST
**Interval**: 30 minutes
**Fuzzer start**: Fresh workdir (corpus/crashes cleared, AI cost preserved)

---

## Round 1 — 2026-02-12 02:20:08

### Process Status: RUNNING

### Dashboard Metrics
- Dashboard accessible: YES
- Latest stats: `2026/02/12 02:20:05 candidates=-10 corpus=4586 coverage=62476 exec total=132105 (506/sec) pending=6 reproducing=1 mode=normal`

### Crash Status
- Crash groups: 1
- Crash details:
  - `WARNING in collect_domain_accesses` — logs:7, repros:0, AI:no

### AI Triage Status
- AI page accessible: YES
- Cost tracker: calls:15, cost:USD 0.6763
- Recent AI activity:
```
2026/02/12 02:19:12 VM 6: crash: WARNING in collect_domain_accesses
2026/02/12 02:19:12 VM 6: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 02:19:52 VM 9: crash: WARNING in collect_domain_accesses
2026/02/12 02:19:52 VM 9: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 02:19:52 PROBE: new variant for 'WARNING in collect_domain_accesses' (tier 2)
```

### eBPF Metrics
```
2026/02/12 02:16:03 PROBE: VM 4: eBPF heap monitor deployment queued (loader=/syz-ebpf-loader obj=/probe_ebpf.bpf.o)
2026/02/12 02:16:03 PROBE: VM 0: eBPF heap monitor deployment queued (loader=/syz-ebpf-loader obj=/probe_ebpf.bpf.o)
2026/02/12 02:16:03 PROBE: VM 8: eBPF heap monitor deployment queued (loader=/syz-ebpf-loader obj=/probe_ebpf.bpf.o)
2026/02/12 02:16:03 PROBE: VM 6: eBPF heap monitor deployment queued (loader=/syz-ebpf-loader obj=/probe_ebpf.bpf.o)
2026/02/12 02:18:33 PROBE: VM 8: eBPF heap monitor deployment queued (loader=/syz-ebpf-loader obj=/probe_ebpf.bpf.o)
2026/02/12 02:19:03 PROBE: VM 9: eBPF heap monitor deployment queued (loader=/syz-ebpf-loader obj=/probe_ebpf.bpf.o)
2026/02/12 02:19:14 PROBE: VM 5: eBPF heap monitor deployment queued (loader=/syz-ebpf-loader obj=/probe_ebpf.bpf.o)
2026/02/12 02:19:14 PROBE: VM 2: eBPF heap monitor deployment queued (loader=/syz-ebpf-loader obj=/probe_ebpf.bpf.o)
2026/02/12 02:19:30 PROBE: VM 7: eBPF heap monitor deployment queued (loader=/syz-ebpf-loader obj=/probe_ebpf.bpf.o)
2026/02/12 02:19:31 PROBE: VM 6: eBPF heap monitor deployment queued (loader=/syz-ebpf-loader obj=/probe_ebpf.bpf.o)
```
- eBPF stats from dashboard:
  - Reuses: 				["-"  , 'ebpf allocs: Kernel allocs observed by eBPF per execution'  , 'ebpf reuses: Slab reuses detected by eBPF heap monitor'  , 'ebpf uaf: Non-crashing UAF patterns detected by eBPF' ],
  - UAF: 				["-"  , 'ebpf allocs: Kernel allocs observed by eBPF per execution'  , 'ebpf reuses: Slab reuses detected by eBPF heap monitor'  , 'ebpf uaf: Non-crashing UAF patterns detected by eBPF' ],

### Focus Mode
- Focus starts: 0
0, ends: 0
0

### Log Analysis
- Potential errors found:
```
ioctl$KVM_CAP_EXIT_ON_EMULATION_FAILURE     : fd_kvmvm [ioctl$KVM_CREATE_VM]
ioctl$SNDCTL_SEQ_PANIC                      : fd_seq [openat$sequencer openat$sequencer2]
KCSAN                   : write(/sys/kernel/debug/kcsan, on) failed
2026/02/12 02:18:14 VM 8: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 02:18:36 VM 9: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 02:18:51 VM 5: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 02:18:53 VM 2: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 02:19:01 VM 7: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 02:19:12 VM 6: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 02:19:52 VM 9: crash(tail0): kernel panic: kernel: panic_on_warn set ...
```
- VM connection issues: 0 occurrences
- Latest: `02:20:05 candidates=-10 corpus=4586 coverage=62476 exec total=132105 (506/sec) pending=6 reproducing=1 mode=normal`

### AI Analytics Page
- /ai/analytics page: accessible

### Strategy Status
- Strategy: timestamp:2026-02-12T02:18:11.660073963+09:00, weights:10, seeds:5, focus_targets:0

---

## Round 2 — 2026-02-12 02:50:08

### Process Status: RUNNING

### Dashboard Metrics
- Dashboard accessible: YES
- Latest stats: `2026/02/12 02:50:05 candidates=-10 corpus=11414 coverage=95069 exec total=984482 (477/sec) pending=19 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:syz_open_dev$tty20-ioctl$PIO_UNIMAPCLR]`

### Crash Status
- Crash groups: 6
- Crash details:
  - `WARNING in track_pfn_copy` — logs:1, repros:0, AI:no
  - `lost connection to test machine` — logs:0, repros:3, AI:no
  - `suppressed report` — logs:1, repros:0, AI:no
  - `KASAN: use-after-free Read in mas_next_nentry` — logs:1, repros:0, AI:no
  - `WARNING in collect_domain_accesses` — logs:22, repros:0, AI:no
  - `SYZFAIL: failed to recv rpc` — logs:0, repros:4, AI:no

### AI Triage Status
- AI page accessible: YES
- Cost tracker: calls:15, cost:USD 0.6763
- Recent AI activity:
```
2026/02/12 02:46:58 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=8, rapid=8) in set_mempolicy-syz_open_procfs-syz_clone3-read$FUSE-syz_open_dev$tty20-ioctl$VT_RESIZEX-openat-write$cgroup_pid-read$watch_queue-socket$inet6_tcp-setsockopt$inet6_tcp_int-epoll_create-socket$inet_tcp-epoll_ctl$EPOLL_CTL_ADD-socket$unix-openat-epoll_pwait2-fcntl$dupfd-socket$nl_route-sendmsg$nl_route_sched-ioctl$F2FS_IOC_DECOMPRESS_FILE-ioctl$FS_IOC_SETVERSION-openat$zero-bpf$BPF_PROG_GET_NEXT_ID-bpf$BPF_PROG_GET_FD_BY_ID-close_range-socket$nl_audit-sendmsg$AUDIT_USER_AVC
2026/02/12 02:46:58 PROBE: focus queued 'PROBE:ebpf-uaf:set_mempolicy-syz_open_procfs-syz_clone3-read$FUSE-syz_open_dev$tty20-ioctl$VT_RESIZEX-openat-write$cgroup_pid-read$watch_queue-socket$inet6_tcp-setsockopt$inet6_tcp_int-epoll_create-socket$inet_tcp-epoll_ctl$EPOLL_CTL_ADD-socket$unix-openat-epoll_pwait2-fcntl$dupfd-socket$nl_route-sendmsg$nl_route_sched-ioctl$F2FS_IOC_DECOMPRESS_FILE-ioctl$FS_IOC_SETVERSION-openat$zero-bpf$BPF_PROG_GET_NEXT_ID-bpf$BPF_PROG_GET_FD_BY_ID-close_range-socket$nl_audit-sendmsg$AUDIT_USER_AVC' (pending: 8)
2026/02/12 02:47:51 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=16, rapid=16) in mremap-mlock2-bpf$MAP_CREATE_TAIL_CALL-bpf$MAP_LOOKUP_ELEM-syz_emit_ethernet-syz_open_dev$rtc-openat$loop_ctrl-syz_open_procfs-pipe2-io_uring_enter-ioctl$BTRFS_IOC_BALANCE_V2-ioctl$BTRFS_IOC_DEV_INFO-ioctl$BTRFS_IOC_BALANCE_PROGRESS-ioctl$BTRFS_IOC_BALANCE_V2-syz_open_dev$vcsu-pselect6-rt_tgsigqueueinfo-syz_mount_image$ext4
2026/02/12 02:48:45 VM 6: crash: unregister_netdevice: waiting for DEV to become free
2026/02/12 02:50:06 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=17, rapid=17) in bpf$MAP_CREATE_CONST_STR-socket$nl_audit-syz_open_dev$tty20-ioctl$VT_RESIZEX-sendmsg$netlink-bpf$MAP_UPDATE_CONST_STR-bpf$BPF_MAP_CONST_STR_FREEZE-bpf$PROG_LOAD-syz_open_dev$tty1-socket$packet-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-setsockopt$packet_add_memb-bpf$BPF_BTF_GET_NEXT_ID-bpf$BPF_PROG_WITH_BTFID_LOAD-bpf$MAP_CREATE_TAIL_CALL-bpf$PROG_LOAD-socket$inet_mptcp-setsockopt$sock_linger-ioctl$VT_RESIZE
```

### eBPF Metrics
```
2026/02/12 02:49:26 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=7, rapid=7) in socket$nl_generic-sendmsg$NL80211_CMD_ABORT_SCAN-syz_open_dev$tty20-syz_open_dev$tty20-ioctl$VT_RESIZE
2026/02/12 02:49:29 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=42, rapid=41) in syz_mount_image$ext4-write$FUSE_STATFS-openat$null-prlimit64-mkdirat-truncate
2026/02/12 02:49:31 PROBE: eBPF detected UAF-favorable pattern (score=70, reuse=9, rapid=4) in creat-pwritev-io_uring_setup-syz_clone-prlimit64
2026/02/12 02:49:35 candidates=-10 corpus=11366 coverage=94824 exec total=969598 (477/sec) pending=19 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:syz_open_dev$tty20-ioctl$PIO_UNIMAPCLR]
2026/02/12 02:49:45 candidates=-10 corpus=11380 coverage=94849 exec total=974434 (477/sec) pending=19 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:syz_open_dev$tty20-ioctl$PIO_UNIMAPCLR]
2026/02/12 02:49:48 PROBE: eBPF detected UAF-favorable pattern (score=70, reuse=31, rapid=31) in openat$snapshot-read$snapshot-read$snapshot-perf_event_open$cgroup-syz_clone-fcntl$setownex-fcntl$dupfd-recvmsg$unix-gettid-bpf$BPF_PROG_QUERY-socket$packet-openat$loop_ctrl-bpf$BPF_BTF_LOAD-getsockopt$IPT_SO_GET_INFO-syz_open_pts-syz_open_pts-socket$packet-ioctl$sock_SIOCINQ-ioctl$EXT4_IOC_SWAP_BOOT-ioctl$SYNC_IOC_MERGE-lstat-ioctl$SG_BLKSECTGET-setsockopt$SO_TIMESTAMPING-close_range-accept$inet6-ioctl$F2FS_IOC_GARBAGE_COLLECT_RANGE-openat$cgroup_ro-read-quotactl_fd$Q_SETINFO-getsockopt$inet6_tcp_TCP_ZEROCOPY_RECEIVE
2026/02/12 02:49:55 candidates=-10 corpus=11394 coverage=94931 exec total=979429 (477/sec) pending=19 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:syz_open_dev$tty20-ioctl$PIO_UNIMAPCLR]
2026/02/12 02:50:05 candidates=-10 corpus=11414 coverage=95069 exec total=984482 (477/sec) pending=19 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:syz_open_dev$tty20-ioctl$PIO_UNIMAPCLR]
2026/02/12 02:50:06 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=17, rapid=17) in bpf$MAP_CREATE_CONST_STR-socket$nl_audit-syz_open_dev$tty20-ioctl$VT_RESIZEX-sendmsg$netlink-bpf$MAP_UPDATE_CONST_STR-bpf$BPF_MAP_CONST_STR_FREEZE-bpf$PROG_LOAD-syz_open_dev$tty1-socket$packet-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-setsockopt$packet_add_memb-bpf$BPF_BTF_GET_NEXT_ID-bpf$BPF_PROG_WITH_BTFID_LOAD-bpf$MAP_CREATE_TAIL_CALL-bpf$PROG_LOAD-socket$inet_mptcp-setsockopt$sock_linger-ioctl$VT_RESIZE
2026/02/12 02:50:08 PROBE: eBPF detected UAF-favorable pattern (score=80, reuse=4, rapid=4) in syz_emit_ethernet-syz_mount_image$vfat-openat$uinput-writev-syz_mount_image$ext4-bpf$PROG_LOAD-lsetxattr$trusted_overlay_origin
```
- eBPF stats from dashboard:
  - Reuses: 				["-"  , 'ebpf allocs: Kernel allocs observed by eBPF per execution'  , 'ebpf reuses: Slab reuses detected by eBPF heap monitor'  , 'ebpf uaf: Non-crashing UAF patterns detected by eBPF' ],
  - UAF: 				["-"  , 'ebpf allocs: Kernel allocs observed by eBPF per execution'  , 'ebpf reuses: Slab reuses detected by eBPF heap monitor'  , 'ebpf uaf: Non-crashing UAF patterns detected by eBPF' ],

### Focus Mode
- Focus starts: 8, ends: 7
- Recent focus activity:
```
2026/02/12 02:34:30 PROBE: focus mode started for 'PROBE:ebpf-uaf:syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-openat$ptmx-ioctl$TCSETA-syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-ioctl$TIOCGISO7816-syslog-syslog-syslog' (tier 1)
2026/02/12 02:34:42 PROBE: focus mode started for 'PROBE:ebpf-uaf:socket$nl_generic-syz_open_dev$rtc-syz_open_dev$rtc-ioctl$RTC_AIE_ON-ioctl$RTC_WKALM_RD-ioctl$RTC_WKALM_RD-landlock_create_ruleset-landlock_restrict_self-syz_open_dev$tty20-ioctl$PIO_UNIMAPCLR-sendmsg$NL80211_CMD_SET_WOWLAN-sendmsg$NL80211_CMD_SET_WOWLAN-capget-syz_open_procfs-syz_open_procfs-write$cgroup_pressure-openat$dir-openat-pwritev-pwritev-statx-inotify_init-socket$unix-poll-syz_open_dev$rtc-ioctl$RTC_WKALM_RD-symlinkat-io_setup-io_setup-write$cgroup_pid' (tier 1)
2026/02/12 02:39:02 PROBE: focus mode started for 'PROBE:ebpf-uaf:add_key$keyring' (tier 1)
2026/02/12 02:42:39 PROBE: focus mode started for 'PROBE:ebpf-uaf:syz_open_procfs' (tier 1)
2026/02/12 02:46:56 PROBE: focus mode started for 'PROBE:ebpf-uaf:syz_open_dev$tty20-ioctl$PIO_UNIMAPCLR' (tier 1)
2026/02/12 02:34:30 PROBE: focus mode ended for 'PROBE:ebpf-uaf:capset-socket$inet6_tcp-setsockopt$inet6_tcp_TCP_REPAIR' — iters: 300/300, new_coverage: 296, exit_reason: completed, duration: 4m28s
2026/02/12 02:34:42 PROBE: focus mode ended for 'PROBE:ebpf-uaf:syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-openat$ptmx-ioctl$TCSETA-syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-syslog-ioctl$TIOCGISO7816-syslog-syslog-syslog' — iters: 10/300, new_coverage: 10, exit_reason: completed, duration: 11s
2026/02/12 02:39:02 PROBE: focus mode ended for 'PROBE:ebpf-uaf:socket$nl_generic-syz_open_dev$rtc-syz_open_dev$rtc-ioctl$RTC_AIE_ON-ioctl$RTC_WKALM_RD-ioctl$RTC_WKALM_RD-landlock_create_ruleset-landlock_restrict_self-syz_open_dev$tty20-ioctl$PIO_UNIMAPCLR-sendmsg$NL80211_CMD_SET_WOWLAN-sendmsg$NL80211_CMD_SET_WOWLAN-capget-syz_open_procfs-syz_open_procfs-write$cgroup_pressure-openat$dir-openat-pwritev-pwritev-statx-inotify_init-socket$unix-poll-syz_open_dev$rtc-ioctl$RTC_WKALM_RD-symlinkat-io_setup-io_setup-write$cgroup_pid' — iters: 300/300, new_coverage: 296, exit_reason: completed, duration: 4m20s
2026/02/12 02:42:39 PROBE: focus mode ended for 'PROBE:ebpf-uaf:add_key$keyring' — iters: 222/300, new_coverage: 219, exit_reason: completed, duration: 3m37s
2026/02/12 02:46:56 PROBE: focus mode ended for 'PROBE:ebpf-uaf:syz_open_procfs' — iters: 300/300, new_coverage: 284, exit_reason: completed, duration: 4m17s
```
- Pending queue activity:
```
2026/02/12 02:42:41 PROBE: focus queued 'PROBE:ebpf-uaf:open_tree-syz_genetlink_get_family_id$mptcp-prctl$PR_SET_MM_MAP-fsconfig$FSCONFIG_SET_FD-syz_mount_image$ext4' (pending: 8)
2026/02/12 02:46:56 PROBE: focus dequeued 'PROBE:ebpf-uaf:syz_open_dev$tty20-ioctl$PIO_UNIMAPCLR' (remaining: 7)
2026/02/12 02:46:58 PROBE: focus queued 'PROBE:ebpf-uaf:set_mempolicy-syz_open_procfs-syz_clone3-read$FUSE-syz_open_dev$tty20-ioctl$VT_RESIZEX-openat-write$cgroup_pid-read$watch_queue-socket$inet6_tcp-setsockopt$inet6_tcp_int-epoll_create-socket$inet_tcp-epoll_ctl$EPOLL_CTL_ADD-socket$unix-openat-epoll_pwait2-fcntl$dupfd-socket$nl_route-sendmsg$nl_route_sched-ioctl$F2FS_IOC_DECOMPRESS_FILE-ioctl$FS_IOC_SETVERSION-openat$zero-bpf$BPF_PROG_GET_NEXT_ID-bpf$BPF_PROG_GET_FD_BY_ID-close_range-socket$nl_audit-sendmsg$AUDIT_USER_AVC' (pending: 8)
```

### Log Analysis
- Potential errors found:
```
2026/02/12 02:32:12 VM 7: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 02:32:15 VM 3: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 02:32:15 VM 3: crash(tail1): SYZFAIL: failed to recv rpc
2026/02/12 02:34:56 VM 7: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 02:35:07 VM 9: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 02:36:02 VM 4: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 02:42:36 repro finished 'WARNING in collect_domain_accesses', repro=true crepro=false desc='SYZFAIL: failed to recv rpc' hub=false from_dashboard=false
2026/02/12 02:44:49 VM 5: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 02:46:43 VM 9: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 02:46:53 VM 4: crash(tail0): kernel panic: kernel: panic_on_warn set ...
```
- VM connection issues: 3 occurrences
- Latest: `02:50:05 candidates=-10 corpus=11414 coverage=95069 exec total=984482 (477/sec) pending=19 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:syz_open_dev$tty20-ioctl$PIO_UNIMAPCLR]`

### AI Analytics Page
- /ai/analytics page: accessible

### Strategy Status
- Strategy: timestamp:2026-02-12T02:18:11.660073963+09:00, weights:10, seeds:5, focus_targets:0

---

## Round 3 — 2026-02-12 03:20:08

### Process Status: RUNNING

### Dashboard Metrics
- Dashboard accessible: YES
- Latest stats: `2026/02/12 03:20:05 candidates=-20 corpus=12970 coverage=103189 exec total=1854444 (480/sec) pending=29 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:syz_init_net_socket$nl_generic-syz_genetlink_get_family_id$netlbl_unlabel-sendmsg$NLBL_UNLABEL_C_STATICREMOVE-syz_clone-ptrace-openat$hpet-syz_clone3-ptrace$peek-fspick-bpf$PROG_LOAD]`

### Crash Status
- Crash groups: 6
- Crash details:
  - `WARNING in track_pfn_copy` — logs:1, repros:0, AI:yes (score:15)
  - `lost connection to test machine` — logs:0, repros:3, AI:no
  - `suppressed report` — logs:1, repros:0, AI:no
  - `KASAN: use-after-free Read in mas_next_nentry` — logs:2, repros:0, AI:yes (score:35)
  - `WARNING in collect_domain_accesses` — logs:34, repros:0, AI:yes (score:15)
  - `SYZFAIL: failed to recv rpc` — logs:0, repros:4, AI:no

### AI Triage Status
- AI page accessible: YES
- Cost tracker: calls:19, cost:USD 0.8052
- Recent AI activity:
```
2026/02/12 03:20:08 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=587, rapid=346) in syz_open_dev$sg-ioctl$SCSI_IOCTL_SEND_COMMAND-connect$netlink-bpf$MAP_CREATE_TAIL_CALL-bpf$PROG_LOAD
2026/02/12 03:20:08 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=587, rapid=346) in syz_genetlink_get_family_id$nl80211-sendmsg$NL80211_CMD_SET_BEACON-seccomp$SECCOMP_SET_MODE_FILTER_LISTENER-epoll_pwait2-socket$nl_generic-add_key$fscrypt_provisioning-ioctl$sock_SIOCSIFVLAN_SET_VLAN_FLAG_CMD-ioctl$BTRFS_IOC_SUBVOL_SETFLAGS-openat$udambuf-sendmsg$DEVLINK_CMD_SB_POOL_GET-fcntl$dupfd-openat$cgroup_ro-statx-statfs-sendmsg$TIPC_NL_MON_GET-sendmsg$NL80211_CMD_SET_WIPHY-syz_init_net_socket$nl_generic-syz_genetlink_get_family_id$netlbl_cipso-sendmsg$NLBL_CIPSOV4_C_LIST
2026/02/12 03:20:08 PROBE: eBPF detected UAF-favorable pattern (score=70, reuse=38, rapid=36) in openat$tun-socketpair$nbd-ioctl$sock_SIOCETHTOOL-ioctl$TUNSETIFF-ioctl$TUNSETTXFILTER-shmget$private-shmctl$IPC_RMID
2026/02/12 03:20:08 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=587, rapid=346) in openat$pidfd-pidfd_send_signal-bpf$MAP_CREATE_TAIL_CALL-bpf$MAP_UPDATE_ELEM_TAIL_CALL-syz_open_dev$ttys-fsetxattr-gettid-ioctl$TIOCSIG-socket$igmp-setsockopt$inet_MCAST_MSFILTER-ptrace$getsig-socket$inet6
2026/02/12 03:20:08 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=587, rapid=346) in syz_open_dev$vcsu-sendmsg$DEVLINK_CMD_SB_TC_POOL_BIND_GET-syz_genetlink_get_family_id$nl80211-ioctl$sock_SIOCGIFINDEX_80211-ioctl$sock_SIOCGIFINDEX_80211-sendmsg$NL80211_CMD_GET_STATION-epoll_create1-epoll_ctl$EPOLL_CTL_ADD-syz_genetlink_get_family_id$SEG6-syz_genetlink_get_family_id$mptcp-preadv-syz_genetlink_get_family_id$devlink-sendmsg$DEVLINK_CMD_SB_POOL_GET-semget$private-semtimedop-socket$nl_generic-sendmsg$MPTCP_PM_CMD_SET_LIMITS-getsockopt$inet6_mreq-bpf$MAP_CREATE_CONST_STR-epoll_ctl$EPOLL_CTL_ADD-socket$igmp-ioctl$SIOCGETMIFCNT_IN6-ioctl$UI_BEGIN_FF_ERASE-bpf$MAP_CREATE_TAIL_CALL-ioctl$FIDEDUPERANGE-syz_open_dev$vcsn-fadvise64-syz_init_net_socket$nl_generic-syz_genetlink_get_family_id$nl802154-sendmsg$NL802154_CMD_SET_ACKREQ_DEFAULT
```

### eBPF Metrics
```
2026/02/12 03:20:08 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=587, rapid=346) in exit-seccomp$SECCOMP_SET_MODE_FILTER_LISTENER
2026/02/12 03:20:08 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=587, rapid=346) in syz_emit_ethernet-openat$zero-socket$inet6_mptcp-getsockopt$SO_TIMESTAMP-bpf$ITER_CREATE-openat$cdrom-ioctl$CDROM_SEND_PACKET-openat$mice-ioctl$int_in-capset-open_tree-fsopen-syz_open_procfs$namespace-setns-bpf$BPF_LINK_CREATE_XDP-ioctl$TIOCGPGRP-getsockopt$sock_cred-read$FUSE-socket$inet_udp-ioctl$sock_inet_SIOCADDRT-sendmsg$unix-mount$tmpfs-socket$nl_generic-syz_open_procfs-preadv-ioctl$KDGKBENT
2026/02/12 03:20:08 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=587, rapid=346) in syz_open_procfs-io_uring_setup-socket$inet6_udp-setsockopt$SO_TIMESTAMPING-io_uring_register$IORING_UNREGISTER_PERSONALITY-mkdirat-openat$dir-fcntl$dupfd-ioctl$FS_IOC_GETFSLABEL-preadv-socket$nl_route-sendmsg$nl_route
2026/02/12 03:20:08 PROBE: eBPF detected UAF-favorable pattern (score=70, reuse=16, rapid=14) in syz_mount_image$fuse-io_uring_setup-mmap-openat$zero-syz_clone-shmat-io_uring_register$IORING_REGISTER_PBUF_RING
2026/02/12 03:20:08 PROBE: eBPF detected UAF-favorable pattern (score=70, reuse=38, rapid=36) in openat$tun-socketpair$nbd-ioctl$sock_SIOCETHTOOL-ioctl$TUNSETIFF-ioctl$TUNSETTXFILTER-shmget$private-shmctl$IPC_RMID
2026/02/12 03:20:08 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=587, rapid=346) in syz_open_procfs$namespace-socket$inet6_udp-socket$inet6_mptcp-syz_open_dev$tty20-ioctl$TIOCVHANGUP-writev-openat$khugepaged_scan-pipe2$watch_queue-socket$inet6_icmp-connect$inet6-pkey_mprotect-openat$tun-ioctl$TUNSETIFF-close_range-bind$inet6-openat$bsg-ioctl$BTRFS_IOC_GET_SUBVOL_ROOTREF-ioctl$BTRFS_IOC_TREE_SEARCH_V2-ioctl$SCSI_IOCTL_GET_IDLUN
2026/02/12 03:20:08 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=587, rapid=346) in openat$pidfd-pidfd_send_signal-bpf$MAP_CREATE_TAIL_CALL-bpf$MAP_UPDATE_ELEM_TAIL_CALL-syz_open_dev$ttys-fsetxattr-gettid-ioctl$TIOCSIG-socket$igmp-setsockopt$inet_MCAST_MSFILTER-ptrace$getsig-socket$inet6
2026/02/12 03:20:08 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=587, rapid=346) in openat$apparmor_thread_exec-mremap-mremap-mmap-fsopen-mlock2-mbind
2026/02/12 03:20:08 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=587, rapid=346) in socket$inet_icmp_raw-setsockopt$inet_opts-ioctl$sock_ipv4_tunnel_SIOCGETTUNNEL-ioctl$sock_ipv4_tunnel_SIOCADDTUNNEL-socket$inet6_icmp-ioctl$sock_SIOCGIFINDEX-ioctl$sock_inet6_SIOCADDRT-ioctl$sock_ipv4_tunnel_SIOCCHGTUNNEL-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-socket$nl_route-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-sendmsg$nl_route
2026/02/12 03:20:08 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=587, rapid=346) in syz_open_dev$vcsu-sendmsg$DEVLINK_CMD_SB_TC_POOL_BIND_GET-syz_genetlink_get_family_id$nl80211-ioctl$sock_SIOCGIFINDEX_80211-ioctl$sock_SIOCGIFINDEX_80211-sendmsg$NL80211_CMD_GET_STATION-epoll_create1-epoll_ctl$EPOLL_CTL_ADD-syz_genetlink_get_family_id$SEG6-syz_genetlink_get_family_id$mptcp-preadv-syz_genetlink_get_family_id$devlink-sendmsg$DEVLINK_CMD_SB_POOL_GET-semget$private-semtimedop-socket$nl_generic-sendmsg$MPTCP_PM_CMD_SET_LIMITS-getsockopt$inet6_mreq-bpf$MAP_CREATE_CONST_STR-epoll_ctl$EPOLL_CTL_ADD-socket$igmp-ioctl$SIOCGETMIFCNT_IN6-ioctl$UI_BEGIN_FF_ERASE-bpf$MAP_CREATE_TAIL_CALL-ioctl$FIDEDUPERANGE-syz_open_dev$vcsn-fadvise64-syz_init_net_socket$nl_generic-syz_genetlink_get_family_id$nl802154-sendmsg$NL802154_CMD_SET_ACKREQ_DEFAULT
```
- eBPF stats from dashboard:
  - Reuses: 				["-"  , 'ebpf allocs: Kernel allocs observed by eBPF per execution'  , 'ebpf reuses: Slab reuses detected by eBPF heap monitor'  , 'ebpf uaf: Non-crashing UAF patterns detected by eBPF' ],
  - UAF: 				["-"  , 'ebpf allocs: Kernel allocs observed by eBPF per execution'  , 'ebpf reuses: Slab reuses detected by eBPF heap monitor'  , 'ebpf uaf: Non-crashing UAF patterns detected by eBPF' ],

### Focus Mode
- Focus starts: 17, ends: 16
- Recent focus activity:
```
2026/02/12 03:09:17 PROBE: focus mode started for 'PROBE:ebpf-uaf:socket$nl_generic-syz_open_dev$rtc-ioctl$RTC_AIE_ON-ioctl$RTC_WKALM_RD-ioctl$RTC_WKALM_RD-landlock_create_ruleset-landlock_restrict_self-syz_open_dev$tty20-ioctl$PIO_UNIMAPCLR-sendmsg$NL80211_CMD_SET_WOWLAN-sendmsg$NL80211_CMD_SET_WOWLAN-capget-syz_open_procfs-syz_open_procfs-write$cgroup_pressure-openat$dir-openat-pwritev-pwritev-statx-inotify_init-socket$unix-syz_open_procfs-writev-poll-syz_open_dev$rtc-ioctl$RTC_WKALM_RD-symlinkat-io_setup-io_setup' (tier 1)
2026/02/12 03:13:19 PROBE: focus mode started for 'PROBE:ebpf-uaf:socket$packet-setsockopt$packet_fanout-setsockopt$packet_fanout_data-setsockopt$packet_fanout_data' (tier 1)
2026/02/12 03:17:36 PROBE: focus mode started for 'PROBE:ebpf-uaf:open_tree-syz_genetlink_get_family_id$mptcp-prctl$PR_SET_MM_MAP-fsconfig$FSCONFIG_SET_FD-syz_mount_image$ext4' (tier 1)
2026/02/12 03:18:50 PROBE: focus mode started for 'PROBE:ebpf-uaf:set_mempolicy-syz_open_procfs-syz_clone3-read$FUSE-syz_open_dev$tty20-ioctl$VT_RESIZEX-openat-write$cgroup_pid-read$watch_queue-socket$inet6_tcp-setsockopt$inet6_tcp_int-epoll_create-socket$inet_tcp-epoll_ctl$EPOLL_CTL_ADD-socket$unix-openat-epoll_pwait2-fcntl$dupfd-socket$nl_route-sendmsg$nl_route_sched-ioctl$F2FS_IOC_DECOMPRESS_FILE-ioctl$FS_IOC_SETVERSION-openat$zero-bpf$BPF_PROG_GET_NEXT_ID-bpf$BPF_PROG_GET_FD_BY_ID-close_range-socket$nl_audit-sendmsg$AUDIT_USER_AVC' (tier 1)
2026/02/12 03:19:58 PROBE: focus mode started for 'PROBE:ebpf-uaf:syz_init_net_socket$nl_generic-syz_genetlink_get_family_id$netlbl_unlabel-sendmsg$NLBL_UNLABEL_C_STATICREMOVE-syz_clone-ptrace-openat$hpet-syz_clone3-ptrace$peek-fspick-bpf$PROG_LOAD' (tier 1)
2026/02/12 03:09:17 PROBE: focus mode ended for 'PROBE:ebpf-uaf:socket$xdp-setsockopt$XDP_UMEM_REG-syz_clone-bpf$BPF_MAP_LOOKUP_AND_DELETE_ELEM-syz_open_procfs-lseek-getpgrp-setpriority-ioctl$sock_SIOCSPGRP-socket$inet6-bpf$MAP_DELETE_BATCH-sendmmsg$inet6-close-syz_open_dev$tty20-syz_open_dev$tty20-ioctl$TCSETS2-ioctl$VT_RESIZE' — iters: 278/300, new_coverage: 249, exit_reason: completed, duration: 5m16s
2026/02/12 03:13:19 PROBE: focus mode ended for 'PROBE:ebpf-uaf:socket$nl_generic-syz_open_dev$rtc-ioctl$RTC_AIE_ON-ioctl$RTC_WKALM_RD-ioctl$RTC_WKALM_RD-landlock_create_ruleset-landlock_restrict_self-syz_open_dev$tty20-ioctl$PIO_UNIMAPCLR-sendmsg$NL80211_CMD_SET_WOWLAN-sendmsg$NL80211_CMD_SET_WOWLAN-capget-syz_open_procfs-syz_open_procfs-write$cgroup_pressure-openat$dir-openat-pwritev-pwritev-statx-inotify_init-socket$unix-syz_open_procfs-writev-poll-syz_open_dev$rtc-ioctl$RTC_WKALM_RD-symlinkat-io_setup-io_setup' — iters: 300/300, new_coverage: 247, exit_reason: completed, duration: 4m1s
2026/02/12 03:17:36 PROBE: focus mode ended for 'PROBE:ebpf-uaf:socket$packet-setsockopt$packet_fanout-setsockopt$packet_fanout_data-setsockopt$packet_fanout_data' — iters: 300/300, new_coverage: 251, exit_reason: completed, duration: 4m17s
2026/02/12 03:18:50 PROBE: focus mode ended for 'PROBE:ebpf-uaf:open_tree-syz_genetlink_get_family_id$mptcp-prctl$PR_SET_MM_MAP-fsconfig$FSCONFIG_SET_FD-syz_mount_image$ext4' — iters: 74/300, new_coverage: 54, exit_reason: completed, duration: 1m14s
2026/02/12 03:19:58 PROBE: focus mode ended for 'PROBE:ebpf-uaf:set_mempolicy-syz_open_procfs-syz_clone3-read$FUSE-syz_open_dev$tty20-ioctl$VT_RESIZEX-openat-write$cgroup_pid-read$watch_queue-socket$inet6_tcp-setsockopt$inet6_tcp_int-epoll_create-socket$inet_tcp-epoll_ctl$EPOLL_CTL_ADD-socket$unix-openat-epoll_pwait2-fcntl$dupfd-socket$nl_route-sendmsg$nl_route_sched-ioctl$F2FS_IOC_DECOMPRESS_FILE-ioctl$FS_IOC_SETVERSION-openat$zero-bpf$BPF_PROG_GET_NEXT_ID-bpf$BPF_PROG_GET_FD_BY_ID-close_range-socket$nl_audit-sendmsg$AUDIT_USER_AVC' — iters: 86/300, new_coverage: 68, exit_reason: completed, duration: 1m8s
```
- Pending queue activity:
```
2026/02/12 03:19:58 PROBE: focus mode ended for 'PROBE:ebpf-uaf:set_mempolicy-syz_open_procfs-syz_clone3-read$FUSE-syz_open_dev$tty20-ioctl$VT_RESIZEX-openat-write$cgroup_pid-read$watch_queue-socket$inet6_tcp-setsockopt$inet6_tcp_int-epoll_create-socket$inet_tcp-epoll_ctl$EPOLL_CTL_ADD-socket$unix-openat-epoll_pwait2-fcntl$dupfd-socket$nl_route-sendmsg$nl_route_sched-ioctl$F2FS_IOC_DECOMPRESS_FILE-ioctl$FS_IOC_SETVERSION-openat$zero-bpf$BPF_PROG_GET_NEXT_ID-bpf$BPF_PROG_GET_FD_BY_ID-close_range-socket$nl_audit-sendmsg$AUDIT_USER_AVC' — iters: 86/300, new_coverage: 68, exit_reason: completed, duration: 1m8s
2026/02/12 03:19:58 PROBE: focus dequeued 'PROBE:ebpf-uaf:syz_init_net_socket$nl_generic-syz_genetlink_get_family_id$netlbl_unlabel-sendmsg$NLBL_UNLABEL_C_STATICREMOVE-syz_clone-ptrace-openat$hpet-syz_clone3-ptrace$peek-fspick-bpf$PROG_LOAD' (remaining: 7)
2026/02/12 03:19:58 PROBE: focus queued 'PROBE:ebpf-uaf:socketpair$unix-setsockopt$sock_int-write' (pending: 8)
```

### Log Analysis
- Potential errors found:
```
2026/02/12 03:18:43 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=475, rapid=297) in ioctl$FS_IOC_GETFSLABEL-syz_open_procfs$namespace-ioctl$BTRFS_IOC_QUOTA_RESCAN_WAIT-signalfd4-ioctl$BINDER_GET_EXTENDED_ERROR-openat$apparmor_task_current-ioctl$FICLONERANGE-socket$nl_generic-syz_genetlink_get_family_id$tipc2-sendmsg$TIPC_NL_SOCK_GET-preadv-getsockopt$inet6_mtu-ioctl$BTRFS_IOC_BALANCE_V2-ioctl$BTRFS_IOC_SCRUB-socket$inet-open_tree-ioctl$TUNGETFEATURES-ioctl$VFAT_IOCTL_READDIR_BOTH-openat$apparmor_thread_exec-getsockopt$packet_buf-openat$zero-ioctl$BTRFS_IOC_GET_SUBVOL_ROOTREF-ioctl$BTRFS_IOC_INO_LOOKUP-rt_sigpending-ioctl$TUNSETFILTEREBPF-inotify_add_watch-ioctl$TIOCNXCL-syz_io_uring_setup-creat-sendmsg$SEG6_CMD_DUMPHMAC
2026/02/12 03:18:57 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=479, rapid=299) in fsopen-pidfd_getfd-setsockopt$netlink_NETLINK_BROADCAST_ERROR-fsmount-bpf$MAP_CREATE_RINGBUF-bpf$PROG_LOAD
2026/02/12 03:18:59 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=482, rapid=299) in socket$nl_generic-setsockopt$netlink_NETLINK_BROADCAST_ERROR-gettimeofday
2026/02/12 03:19:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=492, rapid=299) in socket$nl_generic-sendmsg$DEVLINK_CMD_TRAP_GET-syz_genetlink_get_family_id$nl80211-ioctl$sock_SIOCGIFINDEX_80211-sendmsg$NL80211_CMD_SET_QOS_MAP-syz_genetlink_get_family_id$mptcp-sendmsg$MPTCP_PM_CMD_SET_LIMITS-sendmsg$NL80211_CMD_NEW_INTERFACE-sendmsg$NL80211_CMD_NOTIFY_RADAR-pipe2$watch_queue-setsockopt$netlink_NETLINK_BROADCAST_ERROR-openat$loop_ctrl-prctl$PR_GET_TSC-ioctl$BTRFS_IOC_SCRUB_CANCEL-syz_genetlink_get_family_id$tipc2-sendmsg$TIPC_NL_BEARER_ADD-ioctl$sock_FIOGETOWN-getuid-fstat-syz_clone3-statx-sendmsg$unix-getsockopt$netlink-syz_init_net_socket$nl_generic-syz_genetlink_get_family_id$netlbl_mgmt-sendmsg$NLBL_MGMT_C_LISTALL-pkey_alloc-pkey_mprotect-unlinkat-ioctl$KDDELIO
2026/02/12 03:19:15 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=496, rapid=299) in openat$urandom-ioctl$F2FS_IOC_RESIZE_FS-openat$bsg-ioctl$SG_GET_RESERVED_SIZE-geteuid-quotactl_fd$Q_QUOTAON-pipe2$watch_queue-ioctl$BTRFS_IOC_DEFRAG_RANGE-write$binfmt_register-socket$inet_udp-ioctl$AUTOFS_IOC_READY-socket$nl_audit-syz_clone-setsockopt$sock_cred-ioctl$FS_IOC_GETFSLABEL-ptrace$PTRACE_SECCOMP_GET_METADATA-prctl$PR_GET_NAME-connect$inet6-ioctl$F2FS_IOC_WRITE_CHECKPOINT-socket$inet6_udp-ioctl$sock_inet6_udp_SIOCINQ-socket$nl_generic-syz_genetlink_get_family_id$l2tp-ioctl$RNDZAPENTCNT-syz_genetlink_get_family_id$tipc2-sendmsg$TIPC_NL_NODE_GET-write$P9_RLERRORu-openat$cdrom-getresgid-ioctl$TUNSETGROUP
2026/02/12 03:19:25 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=512, rapid=299) in openat$sw_sync_info-seccomp$SECCOMP_SET_MODE_FILTER_LISTENER-pidfd_getfd-openat$ppp-copy_file_range-ioctl$ifreq_SIOCGIFINDEX_team-sendmsg$inet6-ioctl$AUTOFS_IOC_FAIL-signalfd-openat2$dir-getresuid-syz_genetlink_get_family_id$ipvs-sendmsg$IPVS_CMD_GET_SERVICE-syz_genetlink_get_family_id$tipc-sendmsg$TIPC_CMD_SET_NODE_ADDR-ioctl$PPPIOCSDEBUG-syz_genetlink_get_family_id$nl80211-ioctl$sock_SIOCGIFINDEX_80211-sendmsg$NL80211_CMD_PEER_MEASUREMENT_START-syz_init_net_socket$nl_generic-syz_genetlink_get_family_id$netlbl_mgmt-sendmsg$NLBL_MGMT_C_PROTOCOLS-ioctl$BTRFS_IOC_QUOTA_RESCAN_STATUS-syz_init_net_socket$nl_generic-syz_genetlink_get_family_id$nl802154-sendmsg$NL802154_CMD_SET_CCA_ED_LEVEL-syz_genetlink_get_family_id$ieee802154-sendmsg$IEEE802154_LLSEC_DEL_SECLEVEL-ioctl$EXT4_IOC_GETSTATE-sendmsg$NL802154_CMD_SET_WPAN_PHY_NETNS
2026/02/12 03:19:28 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=519, rapid=299) in io_uring_setup-io_uring_register$IORING_REGISTER_RESTRICTIONS-pkey_alloc-pkey_mprotect-ioctl$AUTOFS_IOC_SETTIMEOUT-ioctl$sock_inet_SIOCSARP-pkey_mprotect-openat$urandom-ioctl$BTRFS_IOC_QGROUP_LIMIT-mmap-io_uring_register$IORING_REGISTER_ENABLE_RINGS-syz_open_dev$evdev-ioctl$EVIOCGEFFECTS-socket$nl_generic-setsockopt$netlink_NETLINK_BROADCAST_ERROR-ioctl$F2FS_IOC_SET_PIN_FILE-ioctl$FITHAW-socket$inet_tcp-setsockopt$EBT_SO_SET_COUNTERS-fstatfs-io_uring_setup-io_uring_register$IORING_REGISTER_FILE_ALLOC_RANGE-ioctl$RNDGETENTCNT-read$FUSE-quotactl_fd$Q_GETNEXTQUOTA-ioctl$ifreq_SIOCGIFINDEX_team-bpf$BPF_BTF_GET_FD_BY_ID-bpf$BPF_BTF_GET_NEXT_ID-bpf$MAP_CREATE_TAIL_CALL-bpf$PROG_LOAD
2026/02/12 03:19:31 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=521, rapid=299) in write$P9_RWALK-socket$inet6-ioctl$EXT4_IOC_GET_ES_CACHE-ioctl$TIOCGSID-ioctl$TIOCGSID-fcntl$lock-write$P9_RLERRORu-write$P9_RLERRORu-ioctl$BTRFS_IOC_QGROUP_CREATE-mount-mount-epoll_create-socket$inet_icmp-epoll_ctl$EPOLL_CTL_MOD-openat$procfs-openat$procfs-fcntl$F_SET_FILE_RW_HINT-fcntl$F_SET_FILE_RW_HINT-syz_genetlink_get_family_id$tipc2-sendmsg$TIPC_NL_MEDIA_SET-sendmsg$TIPC_NL_MEDIA_SET-ioctl$F2FS_IOC_RESERVE_COMPRESS_BLOCKS-getsockopt-getsockopt-sendmsg$nl_generic-quotactl_fd$Q_SYNC-ioctl$BTRFS_IOC_SYNC-socket$nl_generic-socket$nl_generic-syz_genetlink_get_family_id$tipc-sendmsg$TIPC_CMD_GET_LINKS-ioctl$BINDER_CTL_ADD-bind$inet6-bind$inet6-write$P9_RREAD-syz_open_dev$loop-ioctl$BLKRESETZONE-recvmsg-recvfrom-recvfrom
2026/02/12 03:19:36 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=525, rapid=299) in socket$inet_icmp_raw-setsockopt$inet_opts-ioctl$EXT4_IOC_SETFSUUID-socket$inet_udplite-socket$inet_udplite-ioctl$sock_ipv4_tunnel_SIOCGETTUNNEL-timerfd_create-socket$inet_mptcp-listen-pipe2-close-openat$procfs-ppoll-ppoll-timerfd_settime-getsockopt$inet_pktinfo-ioctl$sock_ipv4_tunnel_SIOCADDTUNNEL-socket$inet6_icmp-ioctl$sock_SIOCGIFINDEX-ioctl$sock_inet6_SIOCADDRT-pipe2$9p-ioctl$sock_ipv4_tunnel_SIOCCHGTUNNEL-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-socket$nl_route-io_uring_setup-io_uring_register$IORING_REGISTER_BUFFERS-write$P9_RLERRORu-madvise-socket$inet6_udp
2026/02/12 03:20:06 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=585, rapid=346) in socket$nl_generic-flistxattr-openat$binderfs-ioctl$BINDER_GET_EXTENDED_ERROR-eventfd2-openat$uinput-ioctl$UI_DEV_SETUP-ioctl$UI_DEV_CREATE-ioctl$UI_SET_ABSBIT-quotactl_fd$Q_QUOTAOFF-msgsnd-socket$inet6_tcp-bind$inet6-syz_clone-syz_open_procfs-read$FUSE-syz_open_dev$sg-ioctl$EVIOCGABS20-socketpair$unix-recvfrom$unix-getsockopt$inet_IP_IPSEC_POLICY-signalfd4-newfstatat-statx-read$FUSE-socket$nl_route-sendmsg$nl_route-pread64-syz_open_dev$loop-sendmmsg$unix
```
- VM connection issues: 3 occurrences
- Latest: `03:20:05 candidates=-20 corpus=12970 coverage=103189 exec total=1854444 (480/sec) pending=29 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:syz_init_net_socket$nl_generic-syz_genetlink_get_family_id$netlbl_unlabel-sendmsg$NLBL_UNLABEL_C_STATICREMOVE-syz_clone-ptrace-openat$hpet-syz_clone3-ptrace$peek-fspick-bpf$PROG_LOAD]`

### AI Analytics Page
- /ai/analytics page: accessible

### Strategy Status
- Strategy: timestamp:2026-02-12T03:19:44.123797477+09:00, weights:10, seeds:5, focus_targets:3

---

## Round 4 — 2026-02-12 03:50:09

### Process Status: RUNNING

### Dashboard Metrics
- Dashboard accessible: YES
- Latest stats: `2026/02/12 03:50:05 candidates=-20 corpus=13756 coverage=107202 exec total=2658090 (469/sec) pending=48 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:socketpair$unix-setsockopt$sock_int-write]`

### Crash Status
- Crash groups: 6
- Crash details:
  - `WARNING in track_pfn_copy` — logs:1, repros:0, AI:yes (score:15)
  - `lost connection to test machine` — logs:0, repros:3, AI:no
  - `suppressed report` — logs:1, repros:0, AI:no
  - `KASAN: use-after-free Read in mas_next_nentry` — logs:5, repros:0, AI:yes (score:35)
  - `WARNING in collect_domain_accesses` — logs:55, repros:0, AI:yes (score:15)
  - `SYZFAIL: failed to recv rpc` — logs:0, repros:4, AI:no

### AI Triage Status
- AI page accessible: YES
- Cost tracker: calls:19, cost:USD 0.8052
- Recent AI activity:
```
2026/02/12 03:49:39 PROBE: focus mode started for 'PROBE:ebpf-uaf:socketpair$unix-setsockopt$sock_int-write' (tier 1)
2026/02/12 03:49:45 candidates=-20 corpus=13748 coverage=107154 exec total=2649278 (469/sec) pending=48 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:socketpair$unix-setsockopt$sock_int-write]
2026/02/12 03:49:55 candidates=-20 corpus=13751 coverage=107198 exec total=2653205 (469/sec) pending=48 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:socketpair$unix-setsockopt$sock_int-write]
2026/02/12 03:50:05 candidates=-20 corpus=13756 coverage=107202 exec total=2658090 (469/sec) pending=48 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:socketpair$unix-setsockopt$sock_int-write]
2026/02/12 03:50:06 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=26, rapid=25) in set_mempolicy-syz_open_procfs-read$FUSE-syz_open_dev$tty20-ioctl$VT_RESIZEX-openat-write$cgroup_pid-read$watch_queue-epoll_create-socket$inet_tcp-epoll_ctl$EPOLL_CTL_ADD-openat$procfs-statx-read$FUSE-socket$unix-epoll_pwait2-fcntl$dupfd-ioctl$F2FS_IOC_DECOMPRESS_FILE-ioctl$FS_IOC_SETVERSION-sendmsg$nl_generic-ioctl$F2FS_IOC_RELEASE_VOLATILE_WRITE-openat$zero-bpf$BPF_PROG_GET_NEXT_ID-bpf$BPF_PROG_GET_FD_BY_ID-close_range
```

### eBPF Metrics
```
2026/02/12 03:49:39 PROBE: focus mode started for 'PROBE:ebpf-uaf:socketpair$unix-setsockopt$sock_int-write' (tier 1)
2026/02/12 03:49:45 candidates=-20 corpus=13748 coverage=107154 exec total=2649278 (469/sec) pending=48 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:socketpair$unix-setsockopt$sock_int-write]
2026/02/12 03:49:49 PROBE: eBPF detected UAF-favorable pattern (score=80, reuse=1, rapid=1) in syz_mount_image$ext4-openat-getdents64-ioctl$SG_SET_KEEP_ORPHAN-openat-ioctl$FS_IOC_ADD_ENCRYPTION_KEY-mkdirat-openat-setsockopt$sock_attach_bpf-socket$nl_generic-syz_genetlink_get_family_id$ethtool-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-sendmsg$ETHTOOL_MSG_DEBUG_SET-ioctl$FS_IOC_SET_ENCRYPTION_POLICY-openat-write
2026/02/12 03:49:49 PROBE: focus queued 'PROBE:ebpf-uaf:syz_mount_image$ext4-openat-getdents64-ioctl$SG_SET_KEEP_ORPHAN-openat-ioctl$FS_IOC_ADD_ENCRYPTION_KEY-mkdirat-openat-setsockopt$sock_attach_bpf-socket$nl_generic-syz_genetlink_get_family_id$ethtool-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-sendmsg$ETHTOOL_MSG_DEBUG_SET-ioctl$FS_IOC_SET_ENCRYPTION_POLICY-openat-write' (pending: 8)
2026/02/12 03:49:55 candidates=-20 corpus=13751 coverage=107198 exec total=2653205 (469/sec) pending=48 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:socketpair$unix-setsockopt$sock_int-write]
2026/02/12 03:49:59 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=34, rapid=31) in openat$sysfs-socket$inet6-socket-ioctl$TIOCGPGRP-openat$ppp-bpf$BPF_GET_MAP_INFO-sendmmsg$inet-openat$tun-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-ioctl$TUNSETIFINDEX-ioctl$ifreq_SIOCGIFINDEX_vcan-socket$nl_route-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-socket$inet6_tcp-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-ioctl$sock_inet6_SIOCSIFADDR-ioctl$sock_ipv4_tunnel_SIOCCHGTUNNEL-sendmsg$ETHTOOL_MSG_CHANNELS_GET-ioctl$PPPIOCNEWUNIT-perf_event_open-syz_open_dev$tty20-syz_open_dev$tty20-fanotify_mark-ioctl$VT_RESIZE-sendmmsg$inet6-getpeername$inet6
2026/02/12 03:50:02 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=32, rapid=32) in openat$ppp-ioctl$PPPIOCNEWUNIT-ioctl$PPPIOCSPASS-truncate
2026/02/12 03:50:05 candidates=-20 corpus=13756 coverage=107202 exec total=2658090 (469/sec) pending=48 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:socketpair$unix-setsockopt$sock_int-write]
2026/02/12 03:50:05 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=6, rapid=5) in syz_open_procfs$pagemap-openat$tun-mmap-perf_event_open-ioctl$TUNSETIFF-close_range
2026/02/12 03:50:06 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=26, rapid=25) in set_mempolicy-syz_open_procfs-read$FUSE-syz_open_dev$tty20-ioctl$VT_RESIZEX-openat-write$cgroup_pid-read$watch_queue-epoll_create-socket$inet_tcp-epoll_ctl$EPOLL_CTL_ADD-openat$procfs-statx-read$FUSE-socket$unix-epoll_pwait2-fcntl$dupfd-ioctl$F2FS_IOC_DECOMPRESS_FILE-ioctl$FS_IOC_SETVERSION-sendmsg$nl_generic-ioctl$F2FS_IOC_RELEASE_VOLATILE_WRITE-openat$zero-bpf$BPF_PROG_GET_NEXT_ID-bpf$BPF_PROG_GET_FD_BY_ID-close_range
```
- eBPF stats from dashboard:
  - Reuses: 				["-"  , 'ebpf allocs: Kernel allocs observed by eBPF per execution'  , 'ebpf reuses: Slab reuses detected by eBPF heap monitor'  , 'ebpf uaf: Non-crashing UAF patterns detected by eBPF' ],
  - UAF: 				["-"  , 'ebpf allocs: Kernel allocs observed by eBPF per execution'  , 'ebpf reuses: Slab reuses detected by eBPF heap monitor'  , 'ebpf uaf: Non-crashing UAF patterns detected by eBPF' ],

### Focus Mode
- Focus starts: 25, ends: 24
- Recent focus activity:
```
2026/02/12 03:37:29 PROBE: focus mode started for 'PROBE:ebpf-uaf:futex_waitv-futex_waitv-mknodat-open$dir' (tier 1)
2026/02/12 03:38:10 PROBE: focus mode started for 'PROBE:ebpf-uaf:socket$inet-getsockopt$MRT-syz_open_dev$tty20-ioctl$TIOCSPGRP-ioctl$VT_RESIZE-socket$inet6_udplite-ioctl$sock_inet6_SIOCADDRT-socket$inet_icmp_raw-sendmsg' (tier 1)
2026/02/12 03:42:09 PROBE: focus mode started for 'PROBE:ebpf-uaf:fcntl$dupfd-recvfrom$inet6-sendmsg$unix' (tier 1)
2026/02/12 03:46:37 PROBE: focus mode started for 'PROBE:ebpf-uaf:openat$bsg-socket$inet6-sendmmsg$inet6-ioctl$SG_EMULATED_HOST-socket$nl_route-sendmsg$nl_route-ioctl$BTRFS_IOC_GET_SUBVOL_ROOTREF-ioctl$BTRFS_IOC_GET_SUBVOL_ROOTREF-ioctl$BTRFS_IOC_INO_LOOKUP-syz_open_dev$vcsu-fsconfig$FSCONFIG_SET_STRING-ioctl$SG_SET_RESERVED_SIZE' (tier 1)
2026/02/12 03:49:39 PROBE: focus mode started for 'PROBE:ebpf-uaf:socketpair$unix-setsockopt$sock_int-write' (tier 1)
2026/02/12 03:37:29 PROBE: focus mode ended for 'PROBE:ebpf-uaf:syz_create_resource$binfmt-syz_create_resource$binfmt-openat$binfmt-write$binfmt_elf64-mkdirat-open$dir-syz_mount_image$fuse-linkat-mount$tmpfs-getxattr-close-socket$inet_icmp-socket$inet_icmp-setsockopt$inet_opts-setsockopt$inet_opts-execveat$binfmt-socket$inet_udp-socket$inet_udp-getsockopt$inet_int-socket$inet6_icmp_raw-ioctl$sock_SIOCETHTOOL-ioctl$sock_SIOCETHTOOL' — iters: 300/300, new_coverage: 223, exit_reason: completed, duration: 4m16s
2026/02/12 03:38:10 PROBE: focus mode ended for 'PROBE:ebpf-uaf:futex_waitv-futex_waitv-mknodat-open$dir' — iters: 55/300, new_coverage: 35, exit_reason: completed, duration: 41s
2026/02/12 03:42:09 PROBE: focus mode ended for 'PROBE:ebpf-uaf:socket$inet-getsockopt$MRT-syz_open_dev$tty20-ioctl$TIOCSPGRP-ioctl$VT_RESIZE-socket$inet6_udplite-ioctl$sock_inet6_SIOCADDRT-socket$inet_icmp_raw-sendmsg' — iters: 300/300, new_coverage: 188, exit_reason: completed, duration: 3m59s
2026/02/12 03:46:37 PROBE: focus mode ended for 'PROBE:ebpf-uaf:fcntl$dupfd-recvfrom$inet6-sendmsg$unix' — iters: 300/300, new_coverage: 179, exit_reason: completed, duration: 4m28s
2026/02/12 03:49:39 PROBE: focus mode ended for 'PROBE:ebpf-uaf:openat$bsg-socket$inet6-sendmmsg$inet6-ioctl$SG_EMULATED_HOST-socket$nl_route-sendmsg$nl_route-ioctl$BTRFS_IOC_GET_SUBVOL_ROOTREF-ioctl$BTRFS_IOC_GET_SUBVOL_ROOTREF-ioctl$BTRFS_IOC_INO_LOOKUP-syz_open_dev$vcsu-fsconfig$FSCONFIG_SET_STRING-ioctl$SG_SET_RESERVED_SIZE' — iters: 200/300, new_coverage: 126, exit_reason: completed, duration: 3m2s
```
- Pending queue activity:
```
2026/02/12 03:46:40 PROBE: focus queued 'KASAN: use-after-free Read in mas_next_nentry' (pending: 8)
2026/02/12 03:49:39 PROBE: focus dequeued 'PROBE:ebpf-uaf:socketpair$unix-setsockopt$sock_int-write' (remaining: 7)
2026/02/12 03:49:49 PROBE: focus queued 'PROBE:ebpf-uaf:syz_mount_image$ext4-openat-getdents64-ioctl$SG_SET_KEEP_ORPHAN-openat-ioctl$FS_IOC_ADD_ENCRYPTION_KEY-mkdirat-openat-setsockopt$sock_attach_bpf-socket$nl_generic-syz_genetlink_get_family_id$ethtool-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-sendmsg$ETHTOOL_MSG_DEBUG_SET-ioctl$FS_IOC_SET_ENCRYPTION_POLICY-openat-write' (pending: 8)
```

### Log Analysis
- Potential errors found:
```
2026/02/12 03:39:09 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=2195, rapid=1022) in openat$ttyprintk-ioctl$TIOCL_GETSHIFTSTATE-syz_open_dev$evdev-ioctl$EVIOCSKEYCODE_V2-syz_emit_ethernet-keyctl$KEYCTL_WATCH_KEY-mount_setattr-capset-prctl$PR_SET_MM_EXE_FILE-openat$apparmor_thread_current-openat$apparmor_thread_exec-socket$packet-setsockopt$packet_fanout-syz_emit_ethernet-preadv2-ioctl$TIOCGPGRP-getpgid-sched_getaffinity-capget-bpf$PROG_LOAD-ioctl$AUTOFS_IOC_FAIL
2026/02/12 03:39:18 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=2199, rapid=1022) in openat$tun-capset-capset-ioctl$TUNSETIFF-bpf$MAP_CREATE_CONST_STR-ioctl$AUTOFS_IOC_FAIL-pkey_alloc-pipe2$watch_queue-pipe2$watch_queue-accept4-pkey_free-pkey_mprotect-pkey_mprotect-pkey_mprotect-mkdirat-openat$fuse-mount$fuse-mount$fuse-read$FUSE-write$FUSE_INIT-write$FUSE_INIT-openat$dir-syz_fuse_handle_req-syz_fuse_handle_req-syz_fuse_handle_req-getdents-getdents-socket$igmp6-setsockopt$inet6_int-mmap-semtimedop-semtimedop-socket$packet-syz_emit_ethernet-syz_emit_ethernet-recvfrom-socketpair$unix-recvmsg$unix-socket$inet6-socket$inet6
2026/02/12 03:39:19 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=2200, rapid=1022) in socket$igmp-setsockopt$MRT_INIT-mmap-mremap-syz_init_net_socket$nl_generic-syz_genetlink_get_family_id$netlbl_unlabel-syz_mount_image$fuse-socket$packet-setsockopt$packet_fanout-socket$inet_udp-sendto$inet-sendmsg$NLBL_UNLABEL_C_STATICREMOVE-io_uring_setup-syz_clone-rseq-syz_init_net_socket$nl_generic-syz_init_net_socket$nl_generic-syz_genetlink_get_family_id$netlbl_cipso-open-io_setup-io_submit-sendmsg$NLBL_CIPSOV4_C_ADD-waitid-socket$igmp-syz_open_dev$vcsn-ioctl$BINDER_GET_EXTENDED_ERROR-clock_nanosleep-socket$igmp6-ioctl$sock_proto_private-setsockopt$MRT_ADD_MFC
2026/02/12 03:39:27 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=2202, rapid=1022) in socket$inet6_icmp-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-ioctl$sock_inet6_SIOCADDRT-syz_open_procfs-pipe-vmsplice-close_range-syz_mount_image$fuse-write$cgroup_type-mkdirat-bpf$PROG_LOAD-setsockopt$netlink_NETLINK_BROADCAST_ERROR-mount$cgroup
2026/02/12 03:39:43 VM 9: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 03:43:14 VM 5: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 03:45:04 VM 4: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 03:45:15 VM 8: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 03:46:32 VM 4: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 03:46:39 VM 9: crash(tail0): SYZFAIL: failed to recv rpc
```
- VM connection issues: 6 occurrences
- Latest: `03:50:05 candidates=-20 corpus=13756 coverage=107202 exec total=2658090 (469/sec) pending=48 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:socketpair$unix-setsockopt$sock_int-write]`

### AI Analytics Page
- /ai/analytics page: accessible

### Strategy Status
- Strategy: timestamp:2026-02-12T03:19:44.123797477+09:00, weights:10, seeds:5, focus_targets:3

---

## Round 5 — 2026-02-12 04:20:09

### Process Status: RUNNING

### Dashboard Metrics
- Dashboard accessible: YES
- Latest stats: `2026/02/12 04:20:05 candidates=-20 corpus=14253 coverage=109576 exec total=3329366 (446/sec) pending=53 reproducing=3 mode=FOCUS[PROBE:ebpf-uaf:socket$inet6_udplite-fcntl$F_SET_RW_HINT-openat$userfaultfd-preadv2-ioctl$F2FS_IOC_RELEASE_VOLATILE_WRITE-socket$inet_icmp-syz_genetlink_get_family_id$nl80211-ioctl$sock_SIOCGIFINDEX_80211-ioctl$sock_SIOCGIFINDEX_80211-sendmsg$NL80211_CMD_SET_MESH_CONFIG-openat$binfmt_register-ioctl$EXT4_IOC_PRECACHE_EXTENTS-setsockopt$IP_VS_SO_SET_EDIT-ioctl$SECCOMP_IOCTL_NOTIF_RECV-fcntl$lock-syz_genetlink_get_family_id$nl80211-syz_genetlink_get_family_id$gtp-sendmsg$GTP_CMD_ECHOREQ-prctl$PR_SET_MM_EXE_FILE-getsockopt$inet_tcp_TCP_ZEROCOPY_RECEIVE-socket$nl_route-ioctl$sock_SIOCGIFINDEX_80211-fcntl$setpipe-ioctl$BTRFS_IOC_GET_SUPPORTED_FEATURES-syz_genetlink_get_family_id$nl802154-close_range-close_range-syz_genetlink_get_family_id$nl80211-sendmsg$NL80211_CMD_VENDOR-ioctl$AUTOFS_IOC_CATATONIC]`

### Crash Status
- Crash groups: 8
- Crash details:
  - `WARNING in track_pfn_copy` — logs:1, repros:0, AI:yes (score:15)
  - `lost connection to test machine` — logs:0, repros:3, AI:no
  - `suppressed report` — logs:1, repros:0, AI:no
  - `KASAN: use-after-free Read in mas_next_nentry` — logs:8, repros:0, AI:yes (score:35)
  - `WARNING in collect_domain_accesses` — logs:62, repros:0, AI:yes (score:15)
  - `WARNING in untrack_pfn` — logs:2, repros:0, AI:no
  - `SYZFAIL: failed to recv rpc` — logs:0, repros:4, AI:no
  - `WARNING in ext4_rename` — logs:1, repros:0, AI:no

### AI Triage Status
- AI page accessible: YES
- Cost tracker: calls:20, cost:USD 0.8258
- Recent AI activity:
```
2026/02/12 04:19:44 PROBE: AI: [Step A] 3 crashes to analyze (tier <= 2)
2026/02/12 04:19:44 PROBE: AI: [Step A] [1/3] Analyzing: KASAN: use-after-free Read in mas_next_nentry
2026/02/12 04:19:44 VM 2: crash: WARNING in collect_domain_accesses
2026/02/12 04:19:44 VM 2: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 04:20:09 PROBE: AI: [Step A] [1/3] Done: KASAN: use-after-free Read in mas_next_nentry → score=35, class=dos, vuln=UAF
```

### eBPF Metrics
```
2026/02/12 04:19:27 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=6, rapid=6) in syz_open_dev$tty20-syz_open_dev$tty20-ioctl$VT_RESIZE-ioctl$VT_RESIZE
2026/02/12 04:19:30 PROBE: eBPF detected UAF-favorable pattern (score=70, reuse=22, rapid=15) in futex-mkdirat-mount$fuse
2026/02/12 04:19:35 candidates=-20 corpus=14243 coverage=109540 exec total=3318535 (446/sec) pending=52 reproducing=3 mode=FOCUS[PROBE:ebpf-uaf:socket$inet6_udplite-fcntl$F_SET_RW_HINT-openat$userfaultfd-preadv2-ioctl$F2FS_IOC_RELEASE_VOLATILE_WRITE-socket$inet_icmp-syz_genetlink_get_family_id$nl80211-ioctl$sock_SIOCGIFINDEX_80211-ioctl$sock_SIOCGIFINDEX_80211-sendmsg$NL80211_CMD_SET_MESH_CONFIG-openat$binfmt_register-ioctl$EXT4_IOC_PRECACHE_EXTENTS-setsockopt$IP_VS_SO_SET_EDIT-ioctl$SECCOMP_IOCTL_NOTIF_RECV-fcntl$lock-syz_genetlink_get_family_id$nl80211-syz_genetlink_get_family_id$gtp-sendmsg$GTP_CMD_ECHOREQ-prctl$PR_SET_MM_EXE_FILE-getsockopt$inet_tcp_TCP_ZEROCOPY_RECEIVE-socket$nl_route-ioctl$sock_SIOCGIFINDEX_80211-fcntl$setpipe-ioctl$BTRFS_IOC_GET_SUPPORTED_FEATURES-syz_genetlink_get_family_id$nl802154-close_range-close_range-syz_genetlink_get_family_id$nl80211-sendmsg$NL80211_CMD_VENDOR-ioctl$AUTOFS_IOC_CATATONIC]
2026/02/12 04:19:39 PROBE: eBPF detected UAF-favorable pattern (score=70, reuse=9, rapid=9) in bpf$BPF_BTF_GET_NEXT_ID-close_range-bpf$BPF_BTF_GET_FD_BY_ID-bpf$BPF_BTF_GET_NEXT_ID-bpf$MAP_CREATE_CONST_STR-socket$inet_udp-ioctl$sock_inet_SIOCADDRT-open_by_handle_at-syz_open_dev$tty20-syz_open_dev$tty20-ioctl$VT_RESIZE
2026/02/12 04:19:40 PROBE: eBPF detected UAF-favorable pattern (score=80, reuse=1, rapid=1) in set_mempolicy-syz_open_procfs-socket$nl_route-sendmsg$nl_route-read$FUSE-syz_open_dev$tty20-ioctl$VT_RESIZEX-openat-read$watch_queue-epoll_create-socket$inet_tcp-mknodat-mknodat-renameat2-epoll_ctl$EPOLL_CTL_ADD-socket$unix-epoll_pwait2-fcntl$dupfd-ioctl$F2FS_IOC_DECOMPRESS_FILE-ioctl$FS_IOC_SETVERSION-openat$zero-ioctl-bpf$BPF_PROG_GET_NEXT_ID-bpf$BPF_PROG_GET_FD_BY_ID-close_range
2026/02/12 04:19:45 candidates=-20 corpus=14246 coverage=109545 exec total=3322157 (446/sec) pending=53 reproducing=3 mode=FOCUS[PROBE:ebpf-uaf:socket$inet6_udplite-fcntl$F_SET_RW_HINT-openat$userfaultfd-preadv2-ioctl$F2FS_IOC_RELEASE_VOLATILE_WRITE-socket$inet_icmp-syz_genetlink_get_family_id$nl80211-ioctl$sock_SIOCGIFINDEX_80211-ioctl$sock_SIOCGIFINDEX_80211-sendmsg$NL80211_CMD_SET_MESH_CONFIG-openat$binfmt_register-ioctl$EXT4_IOC_PRECACHE_EXTENTS-setsockopt$IP_VS_SO_SET_EDIT-ioctl$SECCOMP_IOCTL_NOTIF_RECV-fcntl$lock-syz_genetlink_get_family_id$nl80211-syz_genetlink_get_family_id$gtp-sendmsg$GTP_CMD_ECHOREQ-prctl$PR_SET_MM_EXE_FILE-getsockopt$inet_tcp_TCP_ZEROCOPY_RECEIVE-socket$nl_route-ioctl$sock_SIOCGIFINDEX_80211-fcntl$setpipe-ioctl$BTRFS_IOC_GET_SUPPORTED_FEATURES-syz_genetlink_get_family_id$nl802154-close_range-close_range-syz_genetlink_get_family_id$nl80211-sendmsg$NL80211_CMD_VENDOR-ioctl$AUTOFS_IOC_CATATONIC]
2026/02/12 04:19:55 candidates=-20 corpus=14248 coverage=109545 exec total=3325177 (446/sec) pending=53 reproducing=3 mode=FOCUS[PROBE:ebpf-uaf:socket$inet6_udplite-fcntl$F_SET_RW_HINT-openat$userfaultfd-preadv2-ioctl$F2FS_IOC_RELEASE_VOLATILE_WRITE-socket$inet_icmp-syz_genetlink_get_family_id$nl80211-ioctl$sock_SIOCGIFINDEX_80211-ioctl$sock_SIOCGIFINDEX_80211-sendmsg$NL80211_CMD_SET_MESH_CONFIG-openat$binfmt_register-ioctl$EXT4_IOC_PRECACHE_EXTENTS-setsockopt$IP_VS_SO_SET_EDIT-ioctl$SECCOMP_IOCTL_NOTIF_RECV-fcntl$lock-syz_genetlink_get_family_id$nl80211-syz_genetlink_get_family_id$gtp-sendmsg$GTP_CMD_ECHOREQ-prctl$PR_SET_MM_EXE_FILE-getsockopt$inet_tcp_TCP_ZEROCOPY_RECEIVE-socket$nl_route-ioctl$sock_SIOCGIFINDEX_80211-fcntl$setpipe-ioctl$BTRFS_IOC_GET_SUPPORTED_FEATURES-syz_genetlink_get_family_id$nl802154-close_range-close_range-syz_genetlink_get_family_id$nl80211-sendmsg$NL80211_CMD_VENDOR-ioctl$AUTOFS_IOC_CATATONIC]
2026/02/12 04:20:02 PROBE: VM 2: eBPF heap monitor deployment queued (loader=/syz-ebpf-loader obj=/probe_ebpf.bpf.o)
2026/02/12 04:20:05 candidates=-20 corpus=14253 coverage=109576 exec total=3329366 (446/sec) pending=53 reproducing=3 mode=FOCUS[PROBE:ebpf-uaf:socket$inet6_udplite-fcntl$F_SET_RW_HINT-openat$userfaultfd-preadv2-ioctl$F2FS_IOC_RELEASE_VOLATILE_WRITE-socket$inet_icmp-syz_genetlink_get_family_id$nl80211-ioctl$sock_SIOCGIFINDEX_80211-ioctl$sock_SIOCGIFINDEX_80211-sendmsg$NL80211_CMD_SET_MESH_CONFIG-openat$binfmt_register-ioctl$EXT4_IOC_PRECACHE_EXTENTS-setsockopt$IP_VS_SO_SET_EDIT-ioctl$SECCOMP_IOCTL_NOTIF_RECV-fcntl$lock-syz_genetlink_get_family_id$nl80211-syz_genetlink_get_family_id$gtp-sendmsg$GTP_CMD_ECHOREQ-prctl$PR_SET_MM_EXE_FILE-getsockopt$inet_tcp_TCP_ZEROCOPY_RECEIVE-socket$nl_route-ioctl$sock_SIOCGIFINDEX_80211-fcntl$setpipe-ioctl$BTRFS_IOC_GET_SUPPORTED_FEATURES-syz_genetlink_get_family_id$nl802154-close_range-close_range-syz_genetlink_get_family_id$nl80211-sendmsg$NL80211_CMD_VENDOR-ioctl$AUTOFS_IOC_CATATONIC]
2026/02/12 04:20:09 PROBE: eBPF detected UAF-favorable pattern (score=80, reuse=1, rapid=1) in socket$igmp-socket$igmp-socket$inet6_udp-write$P9_RVERSION-process_vm_writev-process_vm_writev-ioctl$sock_SIOCGIFINDEX-sendmmsg$inet
```
- eBPF stats from dashboard:
  - Reuses: 				["-"  , 'ebpf allocs: Kernel allocs observed by eBPF per execution'  , 'ebpf reuses: Slab reuses detected by eBPF heap monitor'  , 'ebpf uaf: Non-crashing UAF patterns detected by eBPF' ],
  - UAF: 				["-"  , 'ebpf allocs: Kernel allocs observed by eBPF per execution'  , 'ebpf reuses: Slab reuses detected by eBPF heap monitor'  , 'ebpf uaf: Non-crashing UAF patterns detected by eBPF' ],

### Focus Mode
- Focus starts: 35, ends: 34
- Recent focus activity:
```
2026/02/12 04:07:02 PROBE: focus mode started for 'PROBE:ebpf-uaf:openat$procfs-read$FUSE-read$FUSE-socket$inet_icmp-getsockopt$inet_buf-syz_mount_image$squashfs' (tier 1)
2026/02/12 04:08:12 PROBE: focus mode started for 'KASAN: use-after-free Read in mas_next_nentry' (tier 1)
2026/02/12 04:08:23 PROBE: focus mode started for 'PROBE:ebpf-uaf:syz_mount_image$ext4-openat-getdents64-ioctl$SG_SET_KEEP_ORPHAN-openat-ioctl$FS_IOC_ADD_ENCRYPTION_KEY-mkdirat-openat-setsockopt$sock_attach_bpf-socket$nl_generic-syz_genetlink_get_family_id$ethtool-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-sendmsg$ETHTOOL_MSG_DEBUG_SET-ioctl$FS_IOC_SET_ENCRYPTION_POLICY-openat-write' (tier 1)
2026/02/12 04:11:53 PROBE: focus mode started for 'PROBE:ebpf-uaf:openat$sw_sync-ioctl$FS_IOC_READ_VERITY_METADATA' (tier 1)
2026/02/12 04:16:41 PROBE: focus mode started for 'PROBE:ebpf-uaf:socket$inet6_udplite-fcntl$F_SET_RW_HINT-openat$userfaultfd-preadv2-ioctl$F2FS_IOC_RELEASE_VOLATILE_WRITE-socket$inet_icmp-syz_genetlink_get_family_id$nl80211-ioctl$sock_SIOCGIFINDEX_80211-ioctl$sock_SIOCGIFINDEX_80211-sendmsg$NL80211_CMD_SET_MESH_CONFIG-openat$binfmt_register-ioctl$EXT4_IOC_PRECACHE_EXTENTS-setsockopt$IP_VS_SO_SET_EDIT-ioctl$SECCOMP_IOCTL_NOTIF_RECV-fcntl$lock-syz_genetlink_get_family_id$nl80211-syz_genetlink_get_family_id$gtp-sendmsg$GTP_CMD_ECHOREQ-prctl$PR_SET_MM_EXE_FILE-getsockopt$inet_tcp_TCP_ZEROCOPY_RECEIVE-socket$nl_route-ioctl$sock_SIOCGIFINDEX_80211-fcntl$setpipe-ioctl$BTRFS_IOC_GET_SUPPORTED_FEATURES-syz_genetlink_get_family_id$nl802154-close_range-close_range-syz_genetlink_get_family_id$nl80211-sendmsg$NL80211_CMD_VENDOR-ioctl$AUTOFS_IOC_CATATONIC' (tier 1)
2026/02/12 04:07:02 PROBE: focus mode ended for 'PROBE:ebpf-uaf:socket$inet6_icmp-setsockopt$inet6_int-add_key$fscrypt_provisioning-request_key-keyctl$search' — iters: 300/300, new_coverage: 114, exit_reason: completed, duration: 4m13s
2026/02/12 04:08:12 PROBE: focus mode ended for 'PROBE:ebpf-uaf:openat$procfs-read$FUSE-read$FUSE-socket$inet_icmp-getsockopt$inet_buf-syz_mount_image$squashfs' — iters: 101/300, new_coverage: 37, exit_reason: completed, duration: 1m10s
2026/02/12 04:08:23 PROBE: focus mode ended for 'KASAN: use-after-free Read in mas_next_nentry' — iters: 0/300, new_coverage: 0, exit_reason: completed, duration: 11s
2026/02/12 04:11:53 PROBE: focus mode ended for 'PROBE:ebpf-uaf:syz_mount_image$ext4-openat-getdents64-ioctl$SG_SET_KEEP_ORPHAN-openat-ioctl$FS_IOC_ADD_ENCRYPTION_KEY-mkdirat-openat-setsockopt$sock_attach_bpf-socket$nl_generic-syz_genetlink_get_family_id$ethtool-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-sendmsg$ETHTOOL_MSG_DEBUG_SET-ioctl$FS_IOC_SET_ENCRYPTION_POLICY-openat-write' — iters: 287/300, new_coverage: 135, exit_reason: completed, duration: 3m30s
2026/02/12 04:16:41 PROBE: focus mode ended for 'PROBE:ebpf-uaf:openat$sw_sync-ioctl$FS_IOC_READ_VERITY_METADATA' — iters: 300/300, new_coverage: 183, exit_reason: completed, duration: 4m48s
```
- Pending queue activity:
```
2026/02/12 04:11:53 PROBE: focus queued 'PROBE:ebpf-uaf:mremap-utimensat-openat$fuse-syz_mount_image$fuse-mount$fuseblk' (pending: 8)
2026/02/12 04:16:41 PROBE: focus dequeued 'PROBE:ebpf-uaf:socket$inet6_udplite-fcntl$F_SET_RW_HINT-openat$userfaultfd-preadv2-ioctl$F2FS_IOC_RELEASE_VOLATILE_WRITE-socket$inet_icmp-syz_genetlink_get_family_id$nl80211-ioctl$sock_SIOCGIFINDEX_80211-ioctl$sock_SIOCGIFINDEX_80211-sendmsg$NL80211_CMD_SET_MESH_CONFIG-openat$binfmt_register-ioctl$EXT4_IOC_PRECACHE_EXTENTS-setsockopt$IP_VS_SO_SET_EDIT-ioctl$SECCOMP_IOCTL_NOTIF_RECV-fcntl$lock-syz_genetlink_get_family_id$nl80211-syz_genetlink_get_family_id$gtp-sendmsg$GTP_CMD_ECHOREQ-prctl$PR_SET_MM_EXE_FILE-getsockopt$inet_tcp_TCP_ZEROCOPY_RECEIVE-socket$nl_route-ioctl$sock_SIOCGIFINDEX_80211-fcntl$setpipe-ioctl$BTRFS_IOC_GET_SUPPORTED_FEATURES-syz_genetlink_get_family_id$nl802154-close_range-close_range-syz_genetlink_get_family_id$nl80211-sendmsg$NL80211_CMD_VENDOR-ioctl$AUTOFS_IOC_CATATONIC' (remaining: 7)
2026/02/12 04:16:46 PROBE: focus queued 'PROBE:ebpf-uaf:syz_emit_ethernet-mkdirat-openat$procfs-preadv-openat$fuse-io_setup-mlockall-syz_io_uring_setup-read$FUSE-write$FUSE_DIRENT-openat$cgroup_devices-openat$sw_sync_info-syz_open_procfs-preadv-io_submit-openat$binfmt_register-write$binfmt_register-io_setup-io_uring_setup-io_uring_register$IORING_REGISTER_BUFFERS-openat$bsg-ioctl$BSG_SET_TIMEOUT-creat-eventfd-io_submit-close_range-fsopen-fsconfig$FSCONFIG_CMD_CREATE-fsmount-mount$fuse' (pending: 8)
```

### Log Analysis
- Potential errors found:
```
2026/02/12 04:12:30 repro finished 'WARNING in ext4_rename', repro=true crepro=false desc='SYZFAIL: failed to recv rpc' hub=false from_dashboard=false
2026/02/12 04:12:42 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=920, rapid=264) in inotify_init1-bpf$PROG_LOAD-fsetxattr$security_capability-getpgid-perf_event_open-ioctl$PERF_EVENT_IOC_RESET-bpf$PROG_LOAD-capset-pkey_mprotect-futex-socket$inet6_tcp-setsockopt$inet6_opts-syz_open_dev$loop-preadv-mmap-setsockopt$inet6_opts-openat$vcsu-ioctl$AUTOFS_IOC_FAIL-bpf$MAP_CREATE_RINGBUF-bpf$PROG_LOAD
2026/02/12 04:12:42 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=920, rapid=264) in syz_clone3-prlimit64-openat$procfs-socket$inet_tcp-ioctl$sock_inet_tcp_SIOCOUTQNSD-pkey_mprotect-mkdirat-syz_open_dev$loop-socket$nl_generic-setsockopt$netlink_NETLINK_BROADCAST_ERROR-ioctl$BLKFLSBUF-fsopen-ioctl$BTRFS_IOC_GET_SUBVOL_INFO-fsconfig$FSCONFIG_CMD_CREATE-fsmount-fsconfig$FSCONFIG_SET_BINARY-mlock2
2026/02/12 04:12:54 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=937, rapid=264) in recvmmsg-openat$full-fstat-ioctl$PPPIOCBRIDGECHAN-syz_genetlink_get_family_id$tipc-write$P9_RLERROR-add_key$keyring-add_key$user-keyctl$invalidate-keyctl$unlink-sendmsg$TIPC_CMD_SET_NODE_ADDR-mlockall
2026/02/12 04:13:06 VM 8: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 04:14:47 VM 9: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 04:17:21 repro finished 'WARNING in collect_domain_accesses', repro=true crepro=false desc='SYZFAIL: failed to recv rpc' hub=false from_dashboard=false
2026/02/12 04:17:57 VM 1: crash(tail0): kernel panic: kernel: panic_on_warn set ...
2026/02/12 04:18:49 repro finished 'KASAN: use-after-free Read in mas_next_nentry', repro=true crepro=false desc='SYZFAIL: failed to recv rpc' hub=false from_dashboard=false
2026/02/12 04:19:44 VM 2: crash(tail0): kernel panic: kernel: panic_on_warn set ...
```
- VM connection issues: 9 occurrences
- Latest: `04:20:05 candidates=-20 corpus=14253 coverage=109576 exec total=3329366 (446/sec) pending=53 reproducing=3 mode=FOCUS[PROBE:ebpf-uaf:socket$inet6_udplite-fcntl$F_SET_RW_HINT-openat$userfaultfd-preadv2-ioctl$F2FS_IOC_RELEASE_VOLATILE_WRITE-socket$inet_icmp-syz_genetlink_get_family_id$nl80211-ioctl$sock_SIOCGIFINDEX_80211-ioctl$sock_SIOCGIFINDEX_80211-sendmsg$NL80211_CMD_SET_MESH_CONFIG-openat$binfmt_register-ioctl$EXT4_IOC_PRECACHE_EXTENTS-setsockopt$IP_VS_SO_SET_EDIT-ioctl$SECCOMP_IOCTL_NOTIF_RECV-fcntl$lock-syz_genetlink_get_family_id$nl80211-syz_genetlink_get_family_id$gtp-sendmsg$GTP_CMD_ECHOREQ-prctl$PR_SET_MM_EXE_FILE-getsockopt$inet_tcp_TCP_ZEROCOPY_RECEIVE-socket$nl_route-ioctl$sock_SIOCGIFINDEX_80211-fcntl$setpipe-ioctl$BTRFS_IOC_GET_SUPPORTED_FEATURES-syz_genetlink_get_family_id$nl802154-close_range-close_range-syz_genetlink_get_family_id$nl80211-sendmsg$NL80211_CMD_VENDOR-ioctl$AUTOFS_IOC_CATATONIC]`

### AI Analytics Page
- /ai/analytics page: accessible

### Strategy Status
- Strategy: timestamp:2026-02-12T03:19:44.123797477+09:00, weights:10, seeds:5, focus_targets:3

---

## Round 6 — 2026-02-12 04:50:09

### Process Status: RUNNING

### Dashboard Metrics
- Dashboard accessible: YES
- Latest stats: `2026/02/12 04:50:05 candidates=-30 corpus=14657 coverage=111740 exec total=4056512 (438/sec) pending=66 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:syz_emit_ethernet-mkdirat-openat$procfs-preadv-openat$fuse-io_setup-mlockall-syz_io_uring_setup-read$FUSE-write$FUSE_DIRENT-openat$cgroup_devices-openat$sw_sync_info-syz_open_procfs-preadv-io_submit-openat$binfmt_register-write$binfmt_register-io_setup-io_uring_setup-io_uring_register$IORING_REGISTER_BUFFERS-openat$bsg-ioctl$BSG_SET_TIMEOUT-creat-eventfd-io_submit-close_range-fsopen-fsconfig$FSCONFIG_CMD_CREATE-fsmount-mount$fuse]`

### Crash Status
- Crash groups: 8
- Crash details:
  - `WARNING in track_pfn_copy` — logs:1, repros:0, AI:yes (score:15)
  - `lost connection to test machine` — logs:0, repros:3, AI:no
  - `suppressed report` — logs:1, repros:0, AI:no
  - `KASAN: use-after-free Read in mas_next_nentry` — logs:10, repros:0, AI:yes (score:35)
  - `WARNING in collect_domain_accesses` — logs:78, repros:0, AI:yes (score:15)
  - `WARNING in untrack_pfn` — logs:2, repros:0, AI:yes (score:15)
  - `SYZFAIL: failed to recv rpc` — logs:0, repros:4, AI:no
  - `WARNING in ext4_rename` — logs:2, repros:0, AI:yes (score:15)

### AI Triage Status
- AI page accessible: YES
- Cost tracker: calls:23, cost:USD 0.9400
- Recent AI activity:
```
2026/02/12 04:50:09 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=546, rapid=206) in syz_emit_ethernet-socket$nl_generic-syz_genetlink_get_family_id$tipc2-sendmsg$TIPC_NL_MON_PEER_GET-openat$cdrom-socket$nl_route-sendmsg$nl_route-socket$nl_audit-openat$cdrom-socket$nl_audit-fstat-socketpair$unix-syz_open_procfs-getpid-sendmsg$unix
2026/02/12 04:50:09 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=546, rapid=206) in socket$inet_udplite-setsockopt$inet_int-syz_mount_image$ext4-waitid$P_PIDFD-socket$packet-fsetxattr$trusted_overlay_origin-truncate
2026/02/12 04:50:09 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=546, rapid=206) in socket$nl_route-sendmsg$nl_route-syz_mount_image$vfat-mknod-open-lsetxattr$security_capability-munlock-madvise-syz_open_dev$sg-keyctl$instantiate-perf_event_open-madvise-sendmsg$TIPC_NL_BEARER_DISABLE-statfs-syz_open_dev$evdev-ioctl$EVIOCRMFF-socketpair$unix-sendmsg$inet-recvmmsg$unix-userfaultfd-mlock2-ioctl$UFFDIO_API-syz_clone-munmap-ioctl$UFFDIO_CONTINUE-pkey_alloc-pkey_mprotect-pselect6-syz_emit_ethernet-openat$full
2026/02/12 04:50:09 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=546, rapid=206) in mkdirat-openat$fuse-socket$nl_audit-fstat-socket$inet_udp-ioctl$sock_inet_SIOCADDRT-setreuid-setresuid-mount$fuse-read$FUSE-socketpair$nbd-ioctl$sock_SIOCETHTOOL-syz_fuse_handle_req-umount2
2026/02/12 04:50:09 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=546, rapid=206) in bpf$MAP_CREATE_TAIL_CALL-bpf$MAP_CREATE_TAIL_CALL-bpf$PROG_LOAD-bpf$PROG_LOAD-io_getevents-io_getevents-syz_clone-bpf$BPF_PROG_ATTACH-syz_open_dev$evdev-io_setup-io_submit-io_submit-openat$ttyS3-ioctl$PIO_SCRNMAP-ioctl$PIO_SCRNMAP-socket$inet_udplite-openat$loop_ctrl-semget-clock_gettime-semtimedop-ioctl$LOOP_CTL_GET_FREE-ioctl$LOOP_CTL_GET_FREE-ioctl$LOOP_CTL_ADD-ioctl$LOOP_CTL_ADD-openat$rfkill-write$rfkill
```

### eBPF Metrics
```
2026/02/12 04:50:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=546, rapid=206) in ioctl$sock_inet_SIOCSARP-madvise-madvise-bpf$PROG_LOAD-add_key$keyring-unlink-shmget-shmat-add_key$keyring
2026/02/12 04:50:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=546, rapid=206) in mmap-madvise-syz_clone-syz_clone-pkey_alloc-pkey_mprotect-select-socket$igmp-syz_emit_ethernet
2026/02/12 04:50:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=546, rapid=206) in mq_open-mq_getsetattr-socket$nl_generic-fstat-ioctl$TIOCGPTPEER-ioctl$TIOCVHANGUP-setfsuid-mkdirat-socket$inet6_udp-ioctl$sock_inet6_SIOCADDRT-openat$cgroup_ro-setsockopt$IPT_SO_SET_ADD_COUNTERS-syz_emit_ethernet-syz_open_procfs-write$FUSE_INIT-ioctl$UFFDIO_CONTINUE
2026/02/12 04:50:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=546, rapid=206) in syz_open_procfs$pagemap-ioctl$TUNSETIFF-ioctl$sock_SIOCGIFINDEX-setsockopt$inet_tcp_TCP_REPAIR-pkey_alloc-pkey_mprotect-perf_event_open$cgroup-close_range-socket$igmp
2026/02/12 04:50:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=546, rapid=206) in mkdirat-openat$fuse-mount$fuse-mkdirat-mount$tmpfs-open$dir-openat$fuse-syz_mount_image$fuse-syz_create_resource$binfmt-openat$binfmt-read$FUSE-syz_fuse_handle_req-umount2
2026/02/12 04:50:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=546, rapid=206) in socket$nl_route-socket$igmp-socket$unix-recvmsg$unix-sendto-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-sendmsg$nl_route
2026/02/12 04:50:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=546, rapid=206) in syz_emit_ethernet-mmap-mlockall-socket$inet6_mptcp-socket$inet6_mptcp-madvise-setsockopt$SO_TIMESTAMP-write$tun
2026/02/12 04:50:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=546, rapid=206) in socket$inet6_icmp_raw-openat$ppp-ioctl$PPPIOCNEWUNIT-ioctl$PPPIOCSMAXCID-pipe2$9p-write$P9_RFSYNC-syz_open_procfs$namespace-ioctl$NS_GET_USERNS-ioctl$FS_IOC_GETVERSION-openat$sw_sync_info-fanotify_init-openat$sysfs-pkey_alloc-pkey_mprotect-openat$uinput-fanotify_mark-close_range
2026/02/12 04:50:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=546, rapid=206) in openat$ttyprintk-socket$nl_sock_diag-ioctl$TIOCCONS-sendmsg$DCCPDIAG_GETSOCK-ioctl$KDSKBSENT-bpf$MAP_CREATE_TAIL_CALL-bpf$PROG_LOAD-syz_open_dev$rtc-epoll_create1-epoll_ctl$EPOLL_CTL_ADD-mkdirat-mount-lchown-sync
2026/02/12 04:50:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=546, rapid=206) in bpf$MAP_CREATE_TAIL_CALL-openat$hwrng-bpf$MAP_CREATE_TAIL_CALL-openat$ptmx-inotify_init-openat$random-ioctl$RNDADDTOENTCNT-openat$sysfs-syz_open_procfs-syz_open_dev$vcsu-socket$inet_mptcp-socket$inet_icmp-syz_open_dev$sg-fsopen-socket$inet6_udp-bpf$MAP_CREATE_CONST_STR-seccomp$SECCOMP_SET_MODE_FILTER_LISTENER-creat-pkey_alloc-socket$igmp-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-sendmmsg$inet-bpf$MAP_CREATE_RINGBUF-bpf$PROG_LOAD-socket$inet_udp-socket$inet6_udplite-recvfrom-shutdown-ioctl$sock_inet_SIOCADDRT
```
- eBPF stats from dashboard:
  - Reuses: 				["-"  , 'ebpf allocs: Kernel allocs observed by eBPF per execution'  , 'ebpf reuses: Slab reuses detected by eBPF heap monitor'  , 'ebpf uaf: Non-crashing UAF patterns detected by eBPF' ],
  - UAF: 				["-"  , 'ebpf allocs: Kernel allocs observed by eBPF per execution'  , 'ebpf reuses: Slab reuses detected by eBPF heap monitor'  , 'ebpf uaf: Non-crashing UAF patterns detected by eBPF' ],

### Focus Mode
- Focus starts: 43, ends: 42
- Recent focus activity:
```
2026/02/12 04:35:59 PROBE: focus mode started for 'PROBE:ebpf-uaf:openat$vcsa-openat$vcsa-semget$private-semtimedop-socket$inet6_mptcp-mkdirat-landlock_create_ruleset-openat$dir-openat$dir-landlock_restrict_self-landlock_restrict_self-openat$bsg-pipe2$watch_queue-socket$igmp-pkey_mprotect-setsockopt$inet_mreq-setsockopt$inet_mreq-syz_emit_ethernet-openat$cdrom-openat$cdrom-read' (tier 1)
2026/02/12 04:36:59 PROBE: focus mode started for 'PROBE:ebpf-uaf:socket$inet_udp-ioctl$sock_inet_SIOCADDRT-syz_mount_image$fuse-mount$cgroup-bpf$BPF_BTF_LOAD-syz_open_procfs-signalfd-ioctl$FIDEDUPERANGE-preadv-bpf$MAP_UPDATE_ELEM' (tier 1)
2026/02/12 04:41:48 PROBE: focus mode started for 'PROBE:ebpf-uaf:syz_mount_image$ext4-userfaultfd-ioctl$UFFDIO_API-ioctl$UFFDIO_REGISTER-ioctl$UFFDIO_WRITEPROTECT-socket$packet-syz_genetlink_get_family_id$nl80211-syz_open_procfs-read$FUSE-syz_clone-ptrace-ptrace-getpid-sendmsg$NL80211_CMD_SET_WIPHY_NETNS-bpf$PROG_LOAD-openat$tcp_congestion-socket$inet6_tcp-dup-ioctl$BLKROSET-getsockopt$inet6_tcp_TCP_ZEROCOPY_RECEIVE-bpf$BPF_GET_MAP_INFO-bind$packet-creat-syz_emit_ethernet-openat$pidfd-pidfd_send_signal-syz_open_dev$tty1-write-setsockopt$inet6_mreq-setsockopt$inet6_MCAST_JOIN_GROUP' (tier 1)
2026/02/12 04:47:40 PROBE: focus mode started for 'PROBE:ebpf-uaf:mremap-utimensat-openat$fuse-syz_mount_image$fuse-mount$fuseblk' (tier 1)
2026/02/12 04:50:03 PROBE: focus mode started for 'PROBE:ebpf-uaf:syz_emit_ethernet-mkdirat-openat$procfs-preadv-openat$fuse-io_setup-mlockall-syz_io_uring_setup-read$FUSE-write$FUSE_DIRENT-openat$cgroup_devices-openat$sw_sync_info-syz_open_procfs-preadv-io_submit-openat$binfmt_register-write$binfmt_register-io_setup-io_uring_setup-io_uring_register$IORING_REGISTER_BUFFERS-openat$bsg-ioctl$BSG_SET_TIMEOUT-creat-eventfd-io_submit-close_range-fsopen-fsconfig$FSCONFIG_CMD_CREATE-fsmount-mount$fuse' (tier 1)
2026/02/12 04:35:59 PROBE: focus mode ended for 'PROBE:ebpf-uaf:openat$procfs-read$FUSE-read$FUSE-io_uring_setup-io_uring_register$IORING_REGISTER_FILE_ALLOC_RANGE-socket$nl_route-sendmsg$nl_route' — iters: 300/300, new_coverage: 141, exit_reason: completed, duration: 4m10s
2026/02/12 04:36:59 PROBE: focus mode ended for 'PROBE:ebpf-uaf:openat$vcsa-openat$vcsa-semget$private-semtimedop-socket$inet6_mptcp-mkdirat-landlock_create_ruleset-openat$dir-openat$dir-landlock_restrict_self-landlock_restrict_self-openat$bsg-pipe2$watch_queue-socket$igmp-pkey_mprotect-setsockopt$inet_mreq-setsockopt$inet_mreq-syz_emit_ethernet-openat$cdrom-openat$cdrom-read' — iters: 61/300, new_coverage: 29, exit_reason: completed, duration: 1m0s
2026/02/12 04:41:48 PROBE: focus mode ended for 'PROBE:ebpf-uaf:socket$inet_udp-ioctl$sock_inet_SIOCADDRT-syz_mount_image$fuse-mount$cgroup-bpf$BPF_BTF_LOAD-syz_open_procfs-signalfd-ioctl$FIDEDUPERANGE-preadv-bpf$MAP_UPDATE_ELEM' — iters: 300/300, new_coverage: 171, exit_reason: completed, duration: 4m48s
2026/02/12 04:47:40 PROBE: focus mode ended for 'PROBE:ebpf-uaf:syz_mount_image$ext4-userfaultfd-ioctl$UFFDIO_API-ioctl$UFFDIO_REGISTER-ioctl$UFFDIO_WRITEPROTECT-socket$packet-syz_genetlink_get_family_id$nl80211-syz_open_procfs-read$FUSE-syz_clone-ptrace-ptrace-getpid-sendmsg$NL80211_CMD_SET_WIPHY_NETNS-bpf$PROG_LOAD-openat$tcp_congestion-socket$inet6_tcp-dup-ioctl$BLKROSET-getsockopt$inet6_tcp_TCP_ZEROCOPY_RECEIVE-bpf$BPF_GET_MAP_INFO-bind$packet-creat-syz_emit_ethernet-openat$pidfd-pidfd_send_signal-syz_open_dev$tty1-write-setsockopt$inet6_mreq-setsockopt$inet6_MCAST_JOIN_GROUP' — iters: 300/300, new_coverage: 178, exit_reason: completed, duration: 5m52s
2026/02/12 04:50:03 PROBE: focus mode ended for 'PROBE:ebpf-uaf:mremap-utimensat-openat$fuse-syz_mount_image$fuse-mount$fuseblk' — iters: 158/300, new_coverage: 80, exit_reason: completed, duration: 2m23s
```
- Pending queue activity:
```
2026/02/12 04:47:40 PROBE: focus queued 'PROBE:ebpf-uaf:syz_mount_image$vfat' (pending: 8)
2026/02/12 04:50:03 PROBE: focus dequeued 'PROBE:ebpf-uaf:syz_emit_ethernet-mkdirat-openat$procfs-preadv-openat$fuse-io_setup-mlockall-syz_io_uring_setup-read$FUSE-write$FUSE_DIRENT-openat$cgroup_devices-openat$sw_sync_info-syz_open_procfs-preadv-io_submit-openat$binfmt_register-write$binfmt_register-io_setup-io_uring_setup-io_uring_register$IORING_REGISTER_BUFFERS-openat$bsg-ioctl$BSG_SET_TIMEOUT-creat-eventfd-io_submit-close_range-fsopen-fsconfig$FSCONFIG_CMD_CREATE-fsmount-mount$fuse' (remaining: 7)
2026/02/12 04:50:03 PROBE: focus queued 'PROBE:ebpf-uaf:socket$nl_route-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-dup-bpf$MAP_CREATE_CONST_STR-syz_open_dev$vcsu-statx-getsockopt$sock_cred-fchown-sendmsg$nl_route' (pending: 8)
```

### Log Analysis
- Potential errors found:
```
2026/02/12 04:48:57 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=461, rapid=175) in pipe2$9p-close_range-write$P9_RLOCK-fcntl$setpipe-fcntl$setpipe-syz_clone-ptrace-ptrace$getregs-socket$nl_generic-openat$bsg-syz_genetlink_get_family_id$ethtool-perf_event_open-close_range-membarrier-setsockopt$netlink_NETLINK_BROADCAST_ERROR-arch_prctl$ARCH_MAP_VDSO_64-ioctl$PERF_EVENT_IOC_SET_FILTER-sendmsg$ETHTOOL_MSG_LINKINFO_GET
2026/02/12 04:48:59 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=462, rapid=175) in bpf$MAP_CREATE_CONST_STR-bpf$MAP_CREATE_CONST_STR-bpf$PROG_LOAD-syz_open_procfs$userns-syz_open_procfs$userns-syz_init_net_socket$nl_generic-syz_init_net_socket$nl_generic-syz_genetlink_get_family_id$netlbl_mgmt-sendmsg$NLBL_MGMT_C_ADD-openat$uinput-openat$uinput-readv-socket$nl_route-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-sendmsg$nl_route-memfd_create-mmap-socket$xdp-getpeername-syz_clone-ioctl$AUTOFS_IOC_FAIL-ioctl$AUTOFS_IOC_FAIL-syz_open_procfs$userns-syz_open_procfs$userns
2026/02/12 04:49:17 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=494, rapid=175) in ioctl$FS_IOC_MEASURE_VERITY-syz_create_resource$binfmt-socket$nl_audit-fstat-setsockopt$netlink_NETLINK_BROADCAST_ERROR-setfsuid-open_by_handle_at-openat$binfmt-syz_fuse_handle_req-syz_mount_image$ext4
2026/02/12 04:49:24 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=495, rapid=176) in arch_prctl$ARCH_GET_XCOMP_PERM-pipe2$9p-write$P9_RMKDIR-socket$inet6_icmp-ioctl$sock_SIOCGIFVLAN_SET_VLAN_FLAG_CMD-ioctl$AUTOFS_IOC_READY-sync_file_range-ioctl$BTRFS_IOC_QUOTA_CTL-ioctl$EXT4_IOC_ALLOC_DA_BLKS-arch_prctl$ARCH_GET_XCOMP_PERM-arch_prctl$ARCH_GET_XCOMP_PERM-openat$cgroup_freezer_state-write$cgroup_freezer_state-ioctl$BTRFS_IOC_QUOTA_RESCAN_WAIT-ioctl$RTC_VL_CLR-fcntl$notify-fchdir-arch_prctl$ARCH_GET_XCOMP_PERM-ioctl$sock_inet_SIOCSIFADDR-ioctl$BTRFS_IOC_SYNC-arch_prctl$ARCH_GET_XCOMP_PERM-quotactl_fd$Q_SETQUOTA-arch_prctl$ARCH_GET_XCOMP_PERM-ioctl$DMA_HEAP_IOCTL_ALLOC-ioctl$sock_SIOCGIFVLAN_GET_VLAN_VID_CMD-arch_prctl$ARCH_GET_XCOMP_PERM-write$P9_RLERRORu-setsockopt$SO_BINDTODEVICE-arch_prctl$ARCH_GET_XCOMP_PERM-arch_prctl$ARCH_GET_XCOMP_PERM
2026/02/12 04:49:25 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=497, rapid=176) in syz_open_dev$ptys-ioctl$TIOCGSERIAL-socket$inet6_udp-setsockopt$inet6_MCAST_LEAVE_GROUP-ioctl$KDSKBMODE-ioctl$AUTOFS_IOC_FAIL-socket$inet_udp-ioctl$FIGETBSZ-syz_clone-openat$apparmor_task_exec-ioctl$FS_IOC_FSSETXATTR-syz_mount_image$fuse-ioctl$FS_IOC_GET_ENCRYPTION_KEY_STATUS-ioctl$KDMKTONE-socket$nl_generic-syz_genetlink_get_family_id$batadv-sendmsg$BATADV_CMD_SET_MESH-socket$inet_tcp-pipe2$watch_queue-syz_genetlink_get_family_id$devlink-sendmsg$DEVLINK_CMD_PORT_GET-ioctl$TIOCL_BLANKSCREEN-setsockopt$inet6_opts-accept4$inet6-ioctl$FS_IOC_GET_ENCRYPTION_POLICY-ioctl$BTRFS_IOC_SUBVOL_SETFLAGS-ioctl$sock_inet6_tcp_SIOCOUTQ-write$FUSE_LK-openat$loop_ctrl-ioctl$LOOP_CTL_REMOVE
2026/02/12 04:49:47 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=502, rapid=177) in socket$nl_route-bpf$MAP_CREATE_CONST_STR-bpf$BPF_MAP_CONST_STR_FREEZE-syz_open_procfs-write$FUSE_NOTIFY_RETRIEVE-bpf$PROG_LOAD-bpf$MAP_CREATE_TAIL_CALL-bpf$PROG_BIND_MAP-socket$inet_udp-epoll_create-syz_open_dev$tty20-socket$inet6_mptcp-write$P9_RLERROR-socket$inet6-socket$nl_sock_diag-pipe2$watch_queue-socket$inet6_icmp-socket$inet6_udp-openat$loop_ctrl-inotify_init-sigaltstack-syz_open_procfs-syz_open_dev$vcsu-socket$inet6_udp-syz_mount_image$ext4-mkdirat-prctl$PR_SET_MM-write-bpf$MAP_CREATE_CONST_STR-sendmsg$nl_route
2026/02/12 04:50:01 repro finished 'KASAN: use-after-free Read in mas_next_nentry', repro=true crepro=false desc='SYZFAIL: failed to recv rpc' hub=false from_dashboard=false
2026/02/12 04:50:03 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=527, rapid=188) in socket$nl_generic-setsockopt$netlink_NETLINK_BROADCAST_ERROR-bpf$PROG_LOAD
2026/02/12 04:50:05 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=527, rapid=188) in socket$nl_route-openat$sr-ioctl$SECCOMP_IOCTL_NOTIF_ADDFD-sendmsg$nl_route-ioctl$AUTOFS_IOC_FAIL-msgctl$IPC_SET-fsetxattr$security_capability-msgget$private-msgsnd
2026/02/12 04:50:07 VM 8: crash(tail0): kernel panic: kernel: panic_on_warn set ...
```
- VM connection issues: 11 occurrences
- Latest: `04:50:05 candidates=-30 corpus=14657 coverage=111740 exec total=4056512 (438/sec) pending=66 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:syz_emit_ethernet-mkdirat-openat$procfs-preadv-openat$fuse-io_setup-mlockall-syz_io_uring_setup-read$FUSE-write$FUSE_DIRENT-openat$cgroup_devices-openat$sw_sync_info-syz_open_procfs-preadv-io_submit-openat$binfmt_register-write$binfmt_register-io_setup-io_uring_setup-io_uring_register$IORING_REGISTER_BUFFERS-openat$bsg-ioctl$BSG_SET_TIMEOUT-creat-eventfd-io_submit-close_range-fsopen-fsconfig$FSCONFIG_CMD_CREATE-fsmount-mount$fuse]`

### AI Analytics Page
- /ai/analytics page: accessible

### Strategy Status
- Strategy: timestamp:2026-02-12T04:21:30.368685186+09:00, weights:10, seeds:5, focus_targets:3

---

## Round 7 — 2026-02-12 05:20:10

### Process Status: RUNNING

### Dashboard Metrics
- Dashboard accessible: YES
- Latest stats: `2026/02/12 05:20:05 candidates=-30 corpus=14957 coverage=112991 exec total=4796802 (433/sec) pending=70 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:accept$inet6-ioctl$sock_SIOCSIFVLAN_SET_VLAN_INGRESS_PRIORITY_CMD-openat$uinput-mmap-ioctl$UI_DEV_SETUP-socket$inet6_mptcp-syz_clone-tgkill-syz_mount_image$fuse-mount$fuseblk-mmap-socket$inet6_icmp_raw-getsockopt$inet6_int-fanotify_init-openat$sysfs-openat$uinput-io_setup-openat$cgroup_pressure-io_cancel-openat$fuse-mremap-ioctl$UI_ABS_SETUP-syz_open_dev$tty20-ioctl$TCXONC-pkey_alloc-pkey_mprotect-socket$packet-sendto-bpf$BPF_BTF_GET_NEXT_ID-close_range]`

### Crash Status
- Crash groups: 9
- Crash details:
  - `WARNING in track_pfn_copy` — logs:1, repros:0, AI:yes (score:15)
  - `lost connection to test machine` — logs:0, repros:3, AI:no
  - `suppressed report` — logs:1, repros:0, AI:no
  - `KASAN: use-after-free Read in mas_next_nentry` — logs:10, repros:0, AI:yes (score:35)
  - `KASAN: use-after-free Read in profile_tick` — logs:1, repros:0, AI:no
  - `WARNING in collect_domain_accesses` — logs:84, repros:0, AI:yes (score:15)
  - `WARNING in untrack_pfn` — logs:3, repros:0, AI:yes (score:15)
  - `SYZFAIL: failed to recv rpc` — logs:0, repros:4, AI:no
  - `WARNING in ext4_rename` — logs:2, repros:0, AI:yes (score:15)

### AI Triage Status
- AI page accessible: YES
- Cost tracker: calls:23, cost:USD 0.9400
- Recent AI activity:
```
2026/02/12 05:20:09 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=400, rapid=150) in socket$inet6_udp-socket$inet6_tcp-socketpair$unix-setsockopt$sock_int-socket$nl_audit-sendmsg$AUDIT_USER_AVC-setsockopt$inet6_tcp_TCP_MD5SIG-setsockopt$inet6_tcp_TCP_MD5SIG-bpf$BPF_BTF_LOAD-syz_open_procfs-openat$cgroup_type-connect$inet6-sendmsg$inet6-syz_mount_image$ext4
2026/02/12 05:20:09 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=400, rapid=150) in syz_clone-syz_io_uring_setup-io_uring_enter-ptrace-waitid-ptrace$getenv-ptrace$PTRACE_GETSIGMASK-socket$nl_route-add_key$keyring-add_key$keyring-keyctl$revoke-sendmsg$nl_route
2026/02/12 05:20:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=400, rapid=150) in add_key$keyring-add_key$keyring-keyctl$KEYCTL_RESTRICT_KEYRING-inotify_init1-keyctl$link-syz_clone-clock_gettime-socket$nl_route-sendmsg$nl_route-futex-bpf$MAP_CREATE_TAIL_CALL-bpf$PROG_LOAD-fcntl$dupfd
2026/02/12 05:20:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=400, rapid=150) in openat$cdrom-openat$procfs-ioctl$int_in-ioctl$int_in-openat$procfs-openat$procfs-syz_clone-timer_create-select-select-pkey_alloc-pkey_alloc-open-open-pkey_mprotect-madvise-pkey_alloc-select-syz_open_procfs-fchownat-fchownat-madvise-madvise-ioctl$CDROMREADAUDIO-socket$inet_tcp-socket$inet_tcp-setsockopt$inet_tcp_TCP_REPAIR-setsockopt$inet_tcp_TCP_REPAIR-sendmsg-socket$igmp-ioctl$sock_inet_SIOCSIFADDR-madvise-syz_open_dev$vcsu-fadvise64-read-socket$nl_audit
2026/02/12 05:20:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=400, rapid=150) in syz_mount_image$ext4-io_setup-io_setup-syz_open_procfs-mkdirat-dup2-bpf$TOKEN_CREATE-creat-io_submit-socketpair$unix-socketpair$unix-landlock_create_ruleset-landlock_create_ruleset-bpf$BPF_BTF_LOAD-socket$inet_udp-clock_gettime-clock_gettime-ppoll-timerfd_create-timerfd_create-mmap-mmap-waitid$P_PIDFD-waitid$P_PIDFD-openat$uinput-ioctl$UI_SET_EVBIT-pselect6-syz_emit_ethernet-syz_emit_ethernet-openat$zero-openat$zero-prctl$PR_GET_THP_DISABLE-read$FUSE-getresgid-syz_emit_ethernet-openat$ttyprintk-ioctl$TIOCSETD
```

### eBPF Metrics
```
2026/02/12 05:20:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=400, rapid=150) in openat$mice-write$FUSE_IOCTL-socket$nl_route-syz_open_dev$tty1-ioctl$KDSKBENT-sendmsg$nl_route-socket$inet6_udplite-setsockopt$inet6_udp_int-socket$inet_tcp-fcntl$dupfd-read$FUSE-socket$nl_audit-getsockopt$sock_buf-getpgrp-tkill-openat$fuse-syz_mount_image$fuse
2026/02/12 05:20:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=400, rapid=150) in socket$nl_route-socket$nl_route-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-sendmsg$nl_route-seccomp$SECCOMP_SET_MODE_FILTER_LISTENER-socket$inet6_icmp_raw-setsockopt$inet6_int-mlockall-madvise-get_mempolicy-timer_create-timer_settime-sendmsg$nl_route
2026/02/12 05:20:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=400, rapid=150) in openat$ptmx-ioctl$TIOCPKT-ioctl$TCSETSF-quotactl$Q_SETQUOTA-ioctl$TCSETSF
2026/02/12 05:20:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=400, rapid=150) in socket$inet6_mptcp-close_range-syz_open_dev$tty20-socket$unix-openat$sysfs-ppoll-openat$sysctl-write$sysctl-syz_genetlink_get_family_id$devlink-sendmsg$DEVLINK_CMD_PORT_SPLIT
2026/02/12 05:20:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=400, rapid=150) in pipe2$9p-write$9p-ioctl$BLKBSZGET-read-write$FUSE_GETXATTR-socket$nl_generic-syz_emit_ethernet-write$P9_RLINK-socket$inet
2026/02/12 05:20:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=400, rapid=150) in add_key$fscrypt_v1-add_key$fscrypt_v1-add_key$keyring-keyctl$search-keyctl$assume_authority-add_key$fscrypt_provisioning-add_key$fscrypt_provisioning-keyctl$KEYCTL_PKEY_SIGN-keyctl$search-keyctl$negate-accept4$inet6-accept4$inet6-getpeername$packet-ioctl$sock_inet6_SIOCSIFADDR-syz_open_dev$rtc-syz_open_dev$rtc-ioctl$RTC_WKALM_SET-ioctl$RTC_WKALM_SET-add_key$user-add_key$user-keyctl$unlink-ioctl$RTC_WIE_OFF-lsetxattr$trusted_overlay_origin-open$dir-open$dir-syz_mount_image$fuse-renameat2-add_key$user-request_key-request_key-add_key$keyring-add_key$keyring-add_key$fscrypt_provisioning-preadv2-openat$vcsa-recvmmsg$unix-getsockopt$sock_cred-sendmsg$unix-syz_genetlink_get_family_id$netlbl_calipso-syz_genetlink_get_family_id$netlbl_calipso
2026/02/12 05:20:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=400, rapid=150) in mlock2-syz_mount_image$ext4-openat$dir-getdents-mbind
2026/02/12 05:20:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=400, rapid=150) in syz_open_procfs-preadv-ioctl$EVIOCGKEYCODE-add_key$keyring
2026/02/12 05:20:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=400, rapid=150) in mkdirat-mount-mkdirat-openat$sr-syz_fuse_handle_req-mknodat-syz_mount_image$fuse-mkdirat-renameat2
2026/02/12 05:20:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=400, rapid=150) in mmap-close_range-mkdirat-landlock_create_ruleset-openat$dir-landlock_add_rule$LANDLOCK_RULE_PATH_BENEATH-mmap
```
- eBPF stats from dashboard:
  - Reuses: 				["-"  , 'ebpf allocs: Kernel allocs observed by eBPF per execution'  , 'ebpf reuses: Slab reuses detected by eBPF heap monitor'  , 'ebpf uaf: Non-crashing UAF patterns detected by eBPF' ],
  - UAF: 				["-"  , 'ebpf allocs: Kernel allocs observed by eBPF per execution'  , 'ebpf reuses: Slab reuses detected by eBPF heap monitor'  , 'ebpf uaf: Non-crashing UAF patterns detected by eBPF' ],

### Focus Mode
- Focus starts: 52, ends: 51
- Recent focus activity:
```
2026/02/12 05:03:10 PROBE: focus mode started for 'PROBE:ebpf-uaf:socket$inet6_icmp_raw-socket$nl_generic-socket$nl_generic-syz_genetlink_get_family_id$ethtool-syz_genetlink_get_family_id$ethtool-sendmsg$ETHTOOL_MSG_PRIVFLAGS_SET-getsockopt$sock_int-bpf$MAP_CREATE_CONST_STR-bpf$MAP_UPDATE_CONST_STR-bpf$MAP_UPDATE_CONST_STR-clock_adjtime-bpf$MAP_LOOKUP_BATCH-readv' (tier 1)
2026/02/12 05:08:40 PROBE: focus mode started for 'PROBE:ebpf-uaf:socket$nl_generic-syz_genetlink_get_family_id$nl80211-sendmsg$NL80211_CMD_SET_POWER_SAVE-syz_genetlink_get_family_id$ethtool-socket$nl_generic-sendmsg$ETHTOOL_MSG_PAUSE_GET' (tier 1)
2026/02/12 05:13:36 PROBE: focus mode started for 'PROBE:ebpf-uaf:syz_mount_image$vfat' (tier 1)
2026/02/12 05:17:41 PROBE: focus mode started for 'PROBE:ebpf-uaf:socket$nl_route-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-dup-bpf$MAP_CREATE_CONST_STR-syz_open_dev$vcsu-statx-getsockopt$sock_cred-fchown-sendmsg$nl_route' (tier 1)
2026/02/12 05:18:51 PROBE: focus mode started for 'PROBE:ebpf-uaf:accept$inet6-ioctl$sock_SIOCSIFVLAN_SET_VLAN_INGRESS_PRIORITY_CMD-openat$uinput-mmap-ioctl$UI_DEV_SETUP-socket$inet6_mptcp-syz_clone-tgkill-syz_mount_image$fuse-mount$fuseblk-mmap-socket$inet6_icmp_raw-getsockopt$inet6_int-fanotify_init-openat$sysfs-openat$uinput-io_setup-openat$cgroup_pressure-io_cancel-openat$fuse-mremap-ioctl$UI_ABS_SETUP-syz_open_dev$tty20-ioctl$TCXONC-pkey_alloc-pkey_mprotect-socket$packet-sendto-bpf$BPF_BTF_GET_NEXT_ID-close_range' (tier 1)
2026/02/12 05:03:10 PROBE: focus mode ended for 'PROBE:ebpf-uaf:socket$nl_route-sendmsg$nl_route-mknod-lsetxattr$trusted_overlay_upper' — iters: 42/300, new_coverage: 20, exit_reason: completed, duration: 48s
2026/02/12 05:08:40 PROBE: focus mode ended for 'PROBE:ebpf-uaf:socket$inet6_icmp_raw-socket$nl_generic-socket$nl_generic-syz_genetlink_get_family_id$ethtool-syz_genetlink_get_family_id$ethtool-sendmsg$ETHTOOL_MSG_PRIVFLAGS_SET-getsockopt$sock_int-bpf$MAP_CREATE_CONST_STR-bpf$MAP_UPDATE_CONST_STR-bpf$MAP_UPDATE_CONST_STR-clock_adjtime-bpf$MAP_LOOKUP_BATCH-readv' — iters: 300/300, new_coverage: 123, exit_reason: completed, duration: 5m30s
2026/02/12 05:13:36 PROBE: focus mode ended for 'PROBE:ebpf-uaf:socket$nl_generic-syz_genetlink_get_family_id$nl80211-sendmsg$NL80211_CMD_SET_POWER_SAVE-syz_genetlink_get_family_id$ethtool-socket$nl_generic-sendmsg$ETHTOOL_MSG_PAUSE_GET' — iters: 300/300, new_coverage: 103, exit_reason: completed, duration: 4m55s
2026/02/12 05:17:41 PROBE: focus mode ended for 'PROBE:ebpf-uaf:syz_mount_image$vfat' — iters: 267/300, new_coverage: 124, exit_reason: completed, duration: 4m5s
2026/02/12 05:18:51 PROBE: focus mode ended for 'PROBE:ebpf-uaf:socket$nl_route-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-dup-bpf$MAP_CREATE_CONST_STR-syz_open_dev$vcsu-statx-getsockopt$sock_cred-fchown-sendmsg$nl_route' — iters: 80/300, new_coverage: 35, exit_reason: completed, duration: 1m10s
```
- Pending queue activity:
```
2026/02/12 05:17:41 PROBE: focus queued 'PROBE:ebpf-uaf:syz_emit_ethernet-openat$cgroup_ro-openat-openat$tun-ioctl$TUNSETIFF-ioctl$TUNSETVNETLE-write$binfmt_elf64-bpf$MAP_CREATE_CONST_STR' (pending: 8)
2026/02/12 05:18:51 PROBE: focus dequeued 'PROBE:ebpf-uaf:accept$inet6-ioctl$sock_SIOCSIFVLAN_SET_VLAN_INGRESS_PRIORITY_CMD-openat$uinput-mmap-ioctl$UI_DEV_SETUP-socket$inet6_mptcp-syz_clone-tgkill-syz_mount_image$fuse-mount$fuseblk-mmap-socket$inet6_icmp_raw-getsockopt$inet6_int-fanotify_init-openat$sysfs-openat$uinput-io_setup-openat$cgroup_pressure-io_cancel-openat$fuse-mremap-ioctl$UI_ABS_SETUP-syz_open_dev$tty20-ioctl$TCXONC-pkey_alloc-pkey_mprotect-socket$packet-sendto-bpf$BPF_BTF_GET_NEXT_ID-close_range' (remaining: 7)
2026/02/12 05:18:54 PROBE: focus queued 'PROBE:ebpf-uaf:socket$inet6-dup2-connect$inet6-socket$nl_route-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-socket$inet6_tcp-getsockopt$inet6_tcp_int-syz_open_dev$vcsu-close_range-syz_open_dev$loop-ioctl$BLKBSZSET-ioctl$IOC_PR_RESERVE-sendmsg$nl_route-openat$ttyS3-ioctl$TIOCCBRK-userfaultfd-ioctl$UFFDIO_API-ioctl$UFFDIO_UNREGISTER-sendmmsg$inet6-socket$inet_udp-sendmmsg$inet-openat$hpet-syz_clone3-sendmsg$ETHTOOL_MSG_LINKSTATE_GET' (pending: 8)
```

### Log Analysis
- Potential errors found:
```
2026/02/12 05:19:34 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=374, rapid=149) in openat$mice-pkey_mprotect-write$FUSE_IOCTL-bpf$PROG_LOAD-openat$binderfs-ioctl$BINDER_GET_EXTENDED_ERROR
2026/02/12 05:19:40 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=381, rapid=149) in socket$nl_generic-syz_genetlink_get_family_id$ethtool-ioctl$ifreq_SIOCGIFINDEX_vcan-ioctl$sock_ipv4_tunnel_SIOCADDTUNNEL-getsockopt$inet6_mreq-sendmsg$ETHTOOL_MSG_PRIVFLAGS_GET-syz_genetlink_get_family_id$devlink-sendmsg$DEVLINK_CMD_TRAP_SET-setsockopt$netlink_NETLINK_BROADCAST_ERROR-openat2$dir-ioctl$FS_IOC_SET_ENCRYPTION_POLICY-setsockopt$packet_fanout-syz_genetlink_get_family_id$nl80211-sendmsg$NL80211_CMD_SET_STATION-sendmsg$NL80211_CMD_LEAVE_OCB-getdents-openat$sysctl-syz_clone-syz_open_procfs-fstat-ioctl$FS_IOC_FSGETXATTR-ioctl$F2FS_IOC_DECOMPRESS_FILE-getpeername-perf_event_open-syz_genetlink_get_family_id$batadv-sendmsg$BATADV_CMD_GET_NEIGHBORS-syz_init_net_socket$nl_generic-syz_genetlink_get_family_id$nl802154-ioctl$sock_SIOCGIFINDEX_802154-sendmsg$NL802154_CMD_SET_SHORT_ADDR
2026/02/12 05:19:48 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=383, rapid=149) in accept$packet-setsockopt$packet_add_memb-ioctl$BTRFS_IOC_LOGICAL_INO-socket$inet6_tcp-socket$inet6_tcp-setsockopt$inet6_tcp_TCP_REPAIR_QUEUE-socket$inet_tcp-ioctl$sock_inet_tcp_SIOCATMARK-setsockopt$inet6_int-openat$vcs-ioctl$FS_IOC_GETFSLABEL-ioctl$FS_IOC_GETFSLABEL-syz_genetlink_get_family_id$nl80211-syz_genetlink_get_family_id$nl80211-sendmsg$NL80211_CMD_SET_QOS_MAP-sendmsg$NL80211_CMD_SET_QOS_MAP-ioctl$TCFLSH-preadv2-ioctl$AUTOFS_IOC_FAIL-epoll_ctl$EPOLL_CTL_ADD-ioctl$BTRFS_IOC_SCRUB-ioctl$BTRFS_IOC_DEV_REPLACE-ioctl$BTRFS_IOC_DEV_REPLACE-syz_genetlink_get_family_id$mptcp-syz_genetlink_get_family_id$mptcp-ioctl$ifreq_SIOCGIFINDEX_batadv_mesh-ioctl$ifreq_SIOCGIFINDEX_batadv_mesh-sendmsg$MPTCP_PM_CMD_ADD_ADDR-sendmsg$MPTCP_PM_CMD_ADD_ADDR-setsockopt$inet6_IPV6_RTHDRDSTOPTS-ioctl$sock_SIOCGIFVLAN_DEL_VLAN_CMD-ioctl$sock_SIOCGIFVLAN_DEL_VLAN_CMD-syz_genetlink_get_family_id$nl80211-sendmsg$NL80211_CMD_DEL_MPATH-ioctl$ifreq_SIOCGIFINDEX_batadv_mesh-syz_genetlink_get_family_id$mptcp-sendmsg$MPTCP_PM_CMD_FLUSH_ADDRS-mmap$binder-mmap$binder-write$FUSE_CREATE_OPEN
2026/02/12 05:19:54 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=390, rapid=149) in syz_open_dev$tty20-socket$inet_udp-socket$inet6-setsockopt$inet6_mreq-setsockopt$inet6_mreq-setsockopt$inet6_group_source_req-sendmsg$inet-ioctl$TIOCSTI-socket$nl_generic-syz_mount_image$ext4-socket$inet6_tcp-setsockopt$inet6_opts-setsockopt$netlink_NETLINK_BROADCAST_ERROR-bpf$PROG_LOAD-bpf$BPF_MAP_LOOKUP_AND_DELETE_ELEM
2026/02/12 05:19:55 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=390, rapid=149) in set_mempolicy-socket$igmp-socket$nl_route-sendmsg$nl_route-socket$inet_mptcp-setsockopt$sock_timeval-ioctl$sock_SIOCGIFCONF-openat$zero-madvise-madvise-setsockopt$MRT_INIT-setsockopt$netlink_NETLINK_BROADCAST_ERROR-ioctl$sock_SIOCGSKNS-openat$binderfs_ctrl-syz_mount_image$ext4-socket$inet_udplite-ioctl$CDROMRESUME
2026/02/12 05:19:56 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=390, rapid=149) in ioctl$sock_SIOCGIFINDEX_80211-sendmsg$NL80211_CMD_TRIGGER_SCAN-socket$nl_generic-syz_genetlink_get_family_id$ethtool-sendmsg$ETHTOOL_MSG_RINGS_SET-syz_genetlink_get_family_id$batadv-sendmsg$BATADV_CMD_TP_METER-ioctl$BTRFS_IOC_WAIT_SYNC-syz_genetlink_get_family_id$ieee802154-sendmsg$IEEE802154_LLSEC_LIST_DEVKEY-bpf$BPF_PROG_RAW_TRACEPOINT_LOAD-ioctl$FITHAW-epoll_create-epoll_ctl$EPOLL_CTL_DEL-sendmsg$NL80211_CMD_ABORT_SCAN-openat$procfs-syz_init_net_socket$nl_generic-syz_genetlink_get_family_id$nl802154-ioctl$sock_SIOCGIFINDEX_802154-sendmsg$NL802154_CMD_DEL_SEC_DEVKEY-sendmsg$NL80211_CMD_DISASSOCIATE-ioctl$sock_SIOCGIFINDEX_802154-sendmsg$NL802154_CMD_SET_ACKREQ_DEFAULT-ioctl$FS_IOC_GETFSLABEL-ioctl$sock_ipv6_tunnel_SIOCGETTUNNEL-bpf$PROG_LOAD_XDP-ioctl$AUTOFS_IOC_FAIL-shmget$private-pipe2-sendmsg$NL80211_CMD_PROBE_MESH_LINK
2026/02/12 05:19:56 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=390, rapid=149) in socket$nl_generic-bpf$PROG_LOAD-setsockopt$netlink_NETLINK_BROADCAST_ERROR-socket$inet6_tcp-openat$tun-ioctl$TUNSETIFF-openat$tun-ioctl$TUNSETIFF-getsockopt$inet6_opts
2026/02/12 05:19:57 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=390, rapid=149) in set_mempolicy-socket$igmp-socket$nl_route-set_mempolicy-socket$netlink-capset-syz_genetlink_get_family_id$nl80211-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-syz_open_dev$loop-fsync-sendmsg$nl_route-socket$inet6_mptcp-setsockopt$inet6_tcp_int-socket$nl_generic-syz_genetlink_get_family_id$ethtool-sendmsg$ETHTOOL_MSG_CHANNELS_SET-setsockopt$MRT_INIT-openat$binderfs_ctrl-pipe2$9p-write$P9_RLERROR-fcntl$setpipe-syz_mount_image$ext4
2026/02/12 05:19:58 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=391, rapid=149) in syz_mount_image$vfat-io_uring_setup-socket$nl_route-sendmsg$nl_route-socket$inet_tcp-io_uring_register$IORING_REGISTER_FILES-readlinkat-socket$inet6_tcp-utime-pipe2$9p-write$P9_RLERRORu-write$P9_RUNLINKAT-setsockopt$inet6_tcp_int-syz_create_resource$binfmt-openat$fuse-mount$fuse-read$FUSE-write$FUSE_INIT-syz_fuse_handle_req-syz_fuse_handle_req-quotactl$Q_SETINFO-lsetxattr-openat$binfmt-shmat-openat$binfmt-socket$inet_mptcp-setsockopt$inet_tcp_TCP_CONGESTION-syz_genetlink_get_family_id$ipvs-sendmsg$IPVS_CMD_GET_CONFIG-write
2026/02/12 05:20:09 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=398, rapid=150) in syz_open_dev$vcsa-syz_genetlink_get_family_id$mptcp-write$P9_RLERROR-sendmsg$NL80211_CMD_SET_STATION-ioctl$PIO_CMAP-fsetxattr$security_capability-ioctl$NS_GET_PARENT-openat$uinput-ioctl$UI_SET_SWBIT-syz_genetlink_get_family_id$ipvs-sendmsg$IPVS_CMD_GET_SERVICE-syz_genetlink_get_family_id$nl80211-sendmsg$NL80211_CMD_TESTMODE-ioctl$PIO_FONTRESET-ioctl$PIO_FONTRESET-syz_genetlink_get_family_id$tipc-sendmsg$TIPC_CMD_GET_LINKS-ioctl$UI_GET_VERSION-syz_genetlink_get_family_id$smc-sendmsg$SMC_PNETID_DEL-sendmsg$NL80211_CMD_SET_MAC_ACL-accept4$inet6-ioctl$ifreq_SIOCGIFINDEX_vcan-fsmount-statx-ioctl$BTRFS_IOC_SET_RECEIVED_SUBVOL-ioctl$BTRFS_IOC_RM_DEV_V2-ioctl$sock_SIOCGIFINDEX_80211-sendmsg$NL80211_CMD_ADD_TX_TS-sendmmsg$inet6
```
- VM connection issues: 15 occurrences
- Latest: `05:20:05 candidates=-30 corpus=14957 coverage=112991 exec total=4796802 (433/sec) pending=70 reproducing=2 mode=FOCUS[PROBE:ebpf-uaf:accept$inet6-ioctl$sock_SIOCSIFVLAN_SET_VLAN_INGRESS_PRIORITY_CMD-openat$uinput-mmap-ioctl$UI_DEV_SETUP-socket$inet6_mptcp-syz_clone-tgkill-syz_mount_image$fuse-mount$fuseblk-mmap-socket$inet6_icmp_raw-getsockopt$inet6_int-fanotify_init-openat$sysfs-openat$uinput-io_setup-openat$cgroup_pressure-io_cancel-openat$fuse-mremap-ioctl$UI_ABS_SETUP-syz_open_dev$tty20-ioctl$TCXONC-pkey_alloc-pkey_mprotect-socket$packet-sendto-bpf$BPF_BTF_GET_NEXT_ID-close_range]`

### AI Analytics Page
- /ai/analytics page: accessible

### Strategy Status
- Strategy: timestamp:2026-02-12T04:21:30.368685186+09:00, weights:10, seeds:5, focus_targets:3

---

## Round 8 — 2026-02-12 05:50:11

### Process Status: RUNNING

### Dashboard Metrics
- Dashboard accessible: YES
- Latest stats: `2026/02/12 05:50:05 candidates=-40 corpus=15201 coverage=114275 exec total=5612398 (436/sec) pending=83 reproducing=1 mode=FOCUS[PROBE:ebpf-uaf:socket$nl_generic-getsockopt$netlink-socket$inet6-sendmmsg$inet6]`

### Crash Status
- Crash groups: 9
- Crash details:
  - `WARNING in track_pfn_copy` — logs:1, repros:0, AI:yes (score:15)
  - `lost connection to test machine` — logs:0, repros:3, AI:no
  - `suppressed report` — logs:1, repros:0, AI:no
  - `KASAN: use-after-free Read in mas_next_nentry` — logs:10, repros:0, AI:yes (score:35)
  - `KASAN: use-after-free Read in profile_tick` — logs:1, repros:0, AI:yes (score:25)
  - `WARNING in collect_domain_accesses` — logs:100, repros:0, AI:yes (score:15)
  - `WARNING in untrack_pfn` — logs:3, repros:0, AI:yes (score:15)
  - `SYZFAIL: failed to recv rpc` — logs:0, repros:4, AI:no
  - `WARNING in ext4_rename` — logs:2, repros:0, AI:yes (score:15)

### AI Triage Status
- AI page accessible: YES
- Cost tracker: calls:25, cost:USD 1.0344
- Recent AI activity:
```
2026/02/12 05:50:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5338, rapid=4057) in mkdirat-mount$tmpfs-socketpair$unix-accept4$packet-socket$inet_udp-openat$uinput-ioctl$UI_SET_RELBIT-socket$igmp-sendto$inet-io_setup-syz_open_procfs$pagemap-io_submit-syz_open_procfs-madvise-openat$sysctl-syz_clone-write$sysctl-syz_open_procfs-read$FUSE-socket$inet6_icmp-mkdirat-openat$fuse-mount$fuse-read$FUSE-write$FUSE_INIT-openat$dir-syz_fuse_handle_req-syz_fuse_handle_req-getdents-socket$nl_route
2026/02/12 05:50:10 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5338, rapid=4057) in socket$nl_generic-getsockopt$netlink-socket$inet_tcp-setsockopt$inet_tcp_TCP_REPAIR-setsockopt$inet_tcp_TLS_TX-socket$nl_route-sendmsg$nl_route-read-openat$sr-ioctl$SECCOMP_IOCTL_NOTIF_ADDFD-ioctl$sock_inet_SIOCSIFFLAGS
2026/02/12 05:50:11 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5339, rapid=4057) in socket$nl_route-sendmsg$nl_route-syz_mount_image$fuse-mount$cgroup-sendmsg$nl_route-accept-sendmsg$AUDIT_MAKE_EQUIV-syz_genetlink_get_family_id$batadv-sendmsg$BATADV_CMD_GET_BLA_CLAIM-socket$inet6_udp
2026/02/12 05:50:11 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5339, rapid=4057) in mkdirat-mkdirat-landlock_create_ruleset-openat$dir-landlock_add_rule$LANDLOCK_RULE_PATH_BENEATH-landlock_restrict_self-landlock_create_ruleset-openat$dir-syz_create_resource$binfmt-openat$binfmt-openat$fuse-syz_clone-mount$fuse-socketpair$unix-openat$binfmt-openat$binfmt-landlock_add_rule$LANDLOCK_RULE_PATH_BENEATH-mknodat
2026/02/12 05:50:11 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5339, rapid=4057) in openat$sysctl-write$sysctl-syz_open_dev$tty1-ioctl$TIOCSSOFTCAR-bpf$MAP_UPDATE_ELEM_TAIL_CALL-bpf$TOKEN_CREATE
```

### eBPF Metrics
```
2026/02/12 05:50:11 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5339, rapid=4057) in mmap-openat$cdrom-ioctl$CDROM_SET_OPTIONS-sysfs$2-openat$khugepaged_scan-write$khugepaged_scan-syz_clone-mmap-syz_open_dev$tty1-ioctl$TIOCCONS-getpid-getpriority-sysfs$2-memfd_create-lseek-mount_setattr-madvise-ioctl$FS_IOC_FSSETXATTR-socket$nl_route-socket$inet_udplite-socket$igmp-epoll_create-recvfrom-epoll_ctl$EPOLL_CTL_ADD-shutdown-ioctl$sock_ipv4_tunnel_SIOCCHGTUNNEL-openat-read$FUSE-sendmsg$nl_route-renameat2
2026/02/12 05:50:11 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5339, rapid=4057) in bpf$BPF_BTF_LOAD-openat$incfs-openat$tun-ioctl$TUNSETIFF-openat$vga_arbiter-write$vga_arbiter-mkdirat-syz_genetlink_get_family_id$SEG6-sendto$inet-syz_open_dev$evdev-ioctl$EVIOCGKEYCODE-sendmsg$SEG6_CMD_SETHMAC-openat2$dir-socket$nl_generic-syz_genetlink_get_family_id$mptcp-sendmsg$MPTCP_PM_CMD_ADD_ADDR-syz_mount_image$ext4-bpf$MAP_CREATE_RINGBUF-bpf$BPF_MAP_LOOKUP_AND_DELETE_ELEM-syz_genetlink_get_family_id$nbd-sendmsg$NBD_CMD_CONNECT
2026/02/12 05:50:11 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5339, rapid=4057) in mmap-mmap-mkdirat-socket$nl_generic-connect$netlink-syz_genetlink_get_family_id$nl80211-mount$tmpfs-mount-openat$fuse-mount$fuse
2026/02/12 05:50:11 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5339, rapid=4057) in socket$nl_generic-syz_genetlink_get_family_id$ethtool-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-sendmsg$ETHTOOL_MSG_DEBUG_SET-socket$nl_generic-prctl$PR_SET_VMA-pkey_mprotect-sendmsg$TIPC_NL_LINK_SET-syz_mount_image$ext4
2026/02/12 05:50:11 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5339, rapid=4057) in pipe2-fcntl$lock-fcntl$lock-openat$procfs-read$FUSE-setregid-setfsgid-ioctl$sock_SIOCSIFBR-syz_clone-socket$inet6_udplite-ioctl$sock_ipv6_tunnel_SIOCCHGTUNNEL-ioctl$sock_ipv6_tunnel_SIOCADDTUNNEL-socket$inet6_tcp-sendmsg$inet6-recvmmsg-openat$pidfd
2026/02/12 05:50:11 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5339, rapid=4057) in ioctl$SNAPSHOT_AVAIL_SWAP_SIZE-openat$sysfs-read$FUSE-syz_open_dev$loop
2026/02/12 05:50:11 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5339, rapid=4057) in mkdirat-mount-openat$dir-getdents64
2026/02/12 05:50:11 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5339, rapid=4057) in add_key$keyring-keyctl$clear-syz_open_procfs-pkey_mprotect-preadv-add_key$user-add_key$keyring-add_key$fscrypt_v1-keyctl$KEYCTL_RESTRICT_KEYRING-msgctl$IPC_SET-keyctl$dh_compute
2026/02/12 05:50:11 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5339, rapid=4057) in socket$packet-userfaultfd-ioctl$UFFDIO_API-ioctl$UFFDIO_REGISTER-syz_io_uring_setup-mmap$IORING_OFF_SQ_RING-mmap-getsockopt$packet_int
2026/02/12 05:50:11 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5339, rapid=4057) in socket$netlink-setsockopt$netlink_NETLINK_CAP_ACK-close_range-creat-ioctl$SG_EMULATED_HOST-ioctl$IOC_WATCH_QUEUE_SET_SIZE-ioctl$ifreq_SIOCGIFINDEX_team-bpf$MAP_CREATE_TAIL_CALL-ioctl$sock_SIOCDELDLCI-openat$cdrom
```
- eBPF stats from dashboard:
  - Reuses: 				["-"  , 'ebpf allocs: Kernel allocs observed by eBPF per execution'  , 'ebpf reuses: Slab reuses detected by eBPF heap monitor'  , 'ebpf uaf: Non-crashing UAF patterns detected by eBPF' ],
  - UAF: 				["-"  , 'ebpf allocs: Kernel allocs observed by eBPF per execution'  , 'ebpf reuses: Slab reuses detected by eBPF heap monitor'  , 'ebpf uaf: Non-crashing UAF patterns detected by eBPF' ],

### Focus Mode
- Focus starts: 62, ends: 61
- Recent focus activity:
```
2026/02/12 05:40:19 PROBE: focus mode started for 'PROBE:ebpf-uaf:socket$nl_route-openat$snapshot-write$snapshot-ioctl$SNAPSHOT_FREE-socket$nl_sock_diag-sendmmsg$sock-futex-sendmsg$nl_route' (tier 1)
2026/02/12 05:42:17 PROBE: focus mode started for 'PROBE:ebpf-uaf:syz_emit_ethernet-openat$cgroup_ro-openat-openat$tun-ioctl$TUNSETIFF-ioctl$TUNSETVNETLE-write$binfmt_elf64-bpf$MAP_CREATE_CONST_STR' (tier 1)
2026/02/12 05:42:20 PROBE: focus mode started for 'PROBE:ebpf-uaf:socket$inet6-dup2-connect$inet6-socket$nl_route-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-socket$inet6_tcp-getsockopt$inet6_tcp_int-syz_open_dev$vcsu-close_range-syz_open_dev$loop-ioctl$BLKBSZSET-ioctl$IOC_PR_RESERVE-sendmsg$nl_route-openat$ttyS3-ioctl$TIOCCBRK-userfaultfd-ioctl$UFFDIO_API-ioctl$UFFDIO_UNREGISTER-sendmmsg$inet6-socket$inet_udp-sendmmsg$inet-openat$hpet-syz_clone3-sendmsg$ETHTOOL_MSG_LINKSTATE_GET' (tier 1)
2026/02/12 05:45:29 PROBE: focus mode started for 'PROBE:ebpf-uaf:bpf$MAP_CREATE_TAIL_CALL-bpf$PROG_LOAD-syz_open_dev$sg-ioctl$SG_IO-openat$cgroup_ro-bpf$BPF_BTF_LOAD' (tier 1)
2026/02/12 05:46:37 PROBE: focus mode started for 'PROBE:ebpf-uaf:socket$nl_generic-getsockopt$netlink-socket$inet6-sendmmsg$inet6' (tier 1)
2026/02/12 05:40:19 PROBE: focus mode ended for 'PROBE:ebpf-uaf:syz_socket_connect_nvme_tcp-sendto$inet_nvme_of_msg-socket$inet_icmp_raw-setsockopt$inet_opts-pwritev2-ioctl$sock_FIOSETOWN' — iters: 60/300, new_coverage: 29, exit_reason: completed, duration: 51s
2026/02/12 05:42:17 PROBE: focus mode ended for 'PROBE:ebpf-uaf:socket$nl_route-openat$snapshot-write$snapshot-ioctl$SNAPSHOT_FREE-socket$nl_sock_diag-sendmmsg$sock-futex-sendmsg$nl_route' — iters: 77/300, new_coverage: 37, exit_reason: completed, duration: 1m58s
2026/02/12 05:42:20 PROBE: focus mode ended for 'PROBE:ebpf-uaf:syz_emit_ethernet-openat$cgroup_ro-openat-openat$tun-ioctl$TUNSETIFF-ioctl$TUNSETVNETLE-write$binfmt_elf64-bpf$MAP_CREATE_CONST_STR' — iters: 3/300, new_coverage: 0, exit_reason: completed, duration: 3s
2026/02/12 05:45:29 PROBE: focus mode ended for 'PROBE:ebpf-uaf:socket$inet6-dup2-connect$inet6-socket$nl_route-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-socket$inet6_tcp-getsockopt$inet6_tcp_int-syz_open_dev$vcsu-close_range-syz_open_dev$loop-ioctl$BLKBSZSET-ioctl$IOC_PR_RESERVE-sendmsg$nl_route-openat$ttyS3-ioctl$TIOCCBRK-userfaultfd-ioctl$UFFDIO_API-ioctl$UFFDIO_UNREGISTER-sendmmsg$inet6-socket$inet_udp-sendmmsg$inet-openat$hpet-syz_clone3-sendmsg$ETHTOOL_MSG_LINKSTATE_GET' — iters: 197/300, new_coverage: 88, exit_reason: completed, duration: 3m9s
2026/02/12 05:46:37 PROBE: focus mode ended for 'PROBE:ebpf-uaf:bpf$MAP_CREATE_TAIL_CALL-bpf$PROG_LOAD-syz_open_dev$sg-ioctl$SG_IO-openat$cgroup_ro-bpf$BPF_BTF_LOAD' — iters: 61/300, new_coverage: 23, exit_reason: completed, duration: 1m8s
```
- Pending queue activity:
```
2026/02/12 05:45:29 PROBE: focus queued 'PROBE:ebpf-uaf:openat$procfs-io_uring_setup-syz_open_dev$tty1-ioctl$TIOCL_UNBLANKSCREEN-mlock-mmap$xdp-syz_clone-openat$full-mkdirat-openat$fuse-mount$fuse-syz_fuse_handle_req-fcntl$getown-rt_tgsigqueueinfo-syz_io_uring_setup-gettid-process_vm_readv-syz_open_dev$vcsu-madvise-socket$igmp-setsockopt$inet_opts-read$FUSE-newfstatat-statx-read$FUSE-write$FUSE_STATFS-munlock-eventfd2-fanotify_init-madvise' (pending: 8)
2026/02/12 05:46:37 PROBE: focus dequeued 'PROBE:ebpf-uaf:socket$nl_generic-getsockopt$netlink-socket$inet6-sendmmsg$inet6' (remaining: 7)
2026/02/12 05:46:37 PROBE: focus queued 'PROBE:ebpf-uaf:socket$nl_route-sendmsg$nl_route_sched-unshare-socket$inet6_tcp-sendmmsg$inet6-socket$nl_route-socket$inet6_udp-ioctl$ifreq_SIOCGIFINDEX_batadv_mesh-sendmsg$nl_route-ioctl$sock_SIOCGIFINDEX-sendmsg$nl_route' (pending: 8)
```

### Log Analysis
- Potential errors found:
```
2026/02/12 05:49:00 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5167, rapid=3928) in gettid-process_vm_readv-socket$nl_generic-mknodat-openat$dir-ioctl-socket$inet6-sendmmsg$inet6-socket$inet_tcp-setsockopt$inet_tcp_int-shutdown-setsockopt$netlink_NETLINK_BROADCAST_ERROR-fcntl$dupfd-setsockopt$MRT_DEL_MFC_PROXY-syz_clone3
2026/02/12 05:49:03 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5170, rapid=3928) in sched_setattr-syz_mount_image$ext4-ioctl$int_in-pipe2$9p-write$P9_RLERRORu
2026/02/12 05:49:28 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5187, rapid=3928) in openat$zero-recvmmsg-io_uring_setup-io_uring_register$IORING_REGISTER_RESIZE_RINGS-ioctl$BTRFS_IOC_BALANCE_V2-ioctl$BTRFS_IOC_SCRUB-ioctl$BTRFS_IOC_DEV_INFO-ioctl$BTRFS_IOC_BALANCE_V2-setsockopt$inet_pktinfo-add_key$keyring-add_key$keyring-pselect6-syz_genetlink_get_family_id$mptcp-sendmsg$MPTCP_PM_CMD_SUBFLOW_DESTROY-accept$inet6-io_setup-write$P9_RLERRORu-syz_open_dev$vcsa-ioctl$FICLONE-bpf$BPF_LINK_CREATE-fremovexattr-syz_genetlink_get_family_id$tipc2-sendmsg$TIPC_NL_MEDIA_SET-openat$sw_sync_info-syz_genetlink_get_family_id$ipvs-sendmsg$IPVS_CMD_GET_SERVICE-socket$inet6_tcp-close-write$P9_RUNLINKAT-sendmsg$NL802154_CMD_SET_PAN_ID
2026/02/12 05:49:29 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5187, rapid=3928) in capset-syz_open_procfs-openat$tun-socket$inet6_udp-ioctl$sock_SIOCGIFINDEX-ioctl$TUNSETIFINDEX-ioctl$TUNSETIFF-socket$igmp6-setsockopt$EBT_SO_SET_ENTRIES-socket$netlink-socketpair$unix-bind$unix-connect$unix-setsockopt$netlink_NETLINK_BROADCAST_ERROR
2026/02/12 05:49:31 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5188, rapid=3928) in perf_event_open$cgroup-ioctl$PERF_EVENT_IOC_ID-pselect6-bpf$BPF_MAP_FREEZE-syz_open_dev$loop-syz_open_dev$loop-ioctl$BLKCRYPTOGENERATEKEY-ioctl$PERF_EVENT_IOC_SET_OUTPUT-ioctl$PERF_EVENT_IOC_SET_OUTPUT-socket$inet6_icmp-getsockopt$inet6_IPV6_IPSEC_POLICY-getsockopt$inet6_IPV6_IPSEC_POLICY-syz_open_dev$loop-ioctl$LOOP_GET_STATUS64-pselect6-ioctl$BLKPBSZGET-ioctl$FITRIM-perf_event_open$cgroup-perf_event_open$cgroup-ioctl$PERF_EVENT_IOC_ID-ioctl$PERF_EVENT_IOC_ID-setsockopt$netlink_NETLINK_BROADCAST_ERROR-setsockopt$netlink_NETLINK_BROADCAST_ERROR-ioctl$BTRFS_IOC_SUBVOL_SETFLAGS-syz_open_dev$evdev-ioctl$EVIOCGPHYS-syz_open_dev$tty1-syz_open_dev$tty1-getsockopt$IP_VS_SO_GET_DESTS-getsockopt$IP_VS_SO_GET_DESTS-openat$fuse-read$FUSE-close-close-openat$cdrom-ioctl$CDROMREADAUDIO-ioctl$FS_IOC_FSGETXATTR-ioctl$sock_SIOCSIFVLAN_SET_VLAN_EGRESS_PRIORITY_CMD-fcntl$setlease-fcntl$setlease
2026/02/12 05:49:33 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5188, rapid=3928) in syz_open_dev$tty1-ioctl$TIOCL_PASTESEL-ioctl$GIO_CMAP-syz_open_dev$tty20-ioctl$VT_RESIZE-prctl$PR_SET_THP_DISABLE-openat$fuse-ioctl$VT_ACTIVATE-dup-ioctl$BINDER_GET_EXTENDED_ERROR-openat$sysfs-ioctl$GIO_UNISCRNMAP-pipe2$watch_queue-ioctl$TIOCNOTTY-ioctl$TIOCMBIC-gettid-syz_open_procfs-ioctl$TIOCSETD-ioctl$sock_ipv6_tunnel_SIOCCHGTUNNEL-ioctl$sock_inet6_SIOCSIFDSTADDR-ioctl$VT_SETMODE-setsockopt$IP_VS_SO_SET_DEL-ioctl$KDADDIO-seccomp$SECCOMP_SET_MODE_FILTER_LISTENER-openat$vga_arbiter-ioctl$BTRFS_IOC_RM_DEV-syz_open_dev$tty20-ioctl$TCSETSF-syz_genetlink_get_family_id$tipc2-sendmsg$TIPC_NL_MON_GET
2026/02/12 05:49:59 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5266, rapid=3994) in ioctl$BLKTRACESETUP-capset-socket$inet6_udp-ioctl$F2FS_IOC_SEC_TRIM_FILE-socket$inet6_udplite-sendfile-openat$binderfs-ioctl$BINDER_GET_EXTENDED_ERROR-setsockopt$inet6_udp_int-socket$inet_tcp-setsockopt$inet_tcp_int-openat$tun-ioctl$TUNSETIFF-socket$inet_mptcp-socket$unix-setsockopt$inet_tcp_TCP_REPAIR-openat$sr-newfstatat-setsockopt$sock_cred-shmget$private-shmctl$SHM_STAT-mlock-mknodat$loop-ioctl$TUNSETGROUP-ioctl$VFAT_IOCTL_READDIR_BOTH-mmap-ioctl$sock_SIOCGIFVLAN_SET_VLAN_FLAG_CMD-timer_create-ioctl$GIO_FONT-write$binfmt_elf32
2026/02/12 05:50:03 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5273, rapid=3994) in fcntl$getownex-wait4-bpf$ITER_CREATE-ioctl$sock_inet_tcp_SIOCOUTQNSD-mmap-sendto$inet-getrusage-mincore-ioctl$UI_DEV_SETUP-dup3-epoll_create-mlock2-fsconfig$FSCONFIG_SET_FLAG-accept$inet-accept4$inet-fsconfig$FSCONFIG_SET_FLAG-fsetxattr$trusted_overlay_opaque-ioctl$F2FS_IOC_WRITE_CHECKPOINT-ioctl$BLKFRASET-getsockopt$inet_tcp_TCP_ZEROCOPY_RECEIVE-syz_genetlink_get_family_id$ethtool-sendmsg$ETHTOOL_MSG_WOL_SET-ptrace$ARCH_SET_CPUID-fsconfig$FSCONFIG_CMD_CREATE-ioctl$AUTOFS_IOC_FAIL-stat-quotactl_fd$Q_SETINFO-ioctl$F2FS_IOC_GARBAGE_COLLECT-flock-setsockopt$EBT_SO_SET_ENTRIES
2026/02/12 05:50:04 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5273, rapid=3994) in clock_nanosleep-ioctl$KDFONTOP_SET_DEF-syz_open_procfs-syz_io_uring_setup-timer_delete-ioctl$sock_FIOGETOWN-syz_open_procfs$pagemap-io_uring_setup-timer_getoverrun-syz_open_dev$evdev-openat$apparmor_thread_current-timer_create-timer_getoverrun-timer_gettime-ioctl$EVIOCGPHYS-syz_genetlink_get_family_id$mptcp-sendmsg$MPTCP_PM_CMD_ANNOUNCE-ioctl$DMA_HEAP_IOCTL_ALLOC-syz_genetlink_get_family_id$nl80211-getsockopt$IP6T_SO_GET_INFO-setsockopt$inet6_buf-ioctl$FIDEDUPERANGE-syz_genetlink_get_family_id$tipc-sendmsg$TIPC_CMD_SHOW_STATS-ioctl$PPPIOCGDEBUG-sendmsg$NL80211_CMD_ADD_TX_TS-timer_getoverrun-write$P9_RLERROR-openat$vga_arbiter-fcntl$setownex
2026/02/12 05:50:07 PROBE: eBPF detected UAF-favorable pattern (score=100, reuse=5273, rapid=3994) in creat-pipe2$9p-write$9p-write$P9_RREMOVE-pselect6-fchmod-ioctl$F2FS_IOC_START_VOLATILE_WRITE-ioctl$F2FS_IOC_START_VOLATILE_WRITE-setsockopt$MRT_ASSERT-fcntl$setpipe-bpf$BPF_GET_MAP_INFO-socket$inet6_udp-ioctl$FS_IOC_GET_ENCRYPTION_PWSALT-ioctl$PPPIOCGFLAGS1-ioctl$sock_SIOCGIFINDEX-ioctl$EXT4_IOC_GET_ES_CACHE-ioctl$BTRFS_IOC_TREE_SEARCH_V2-ioctl$BTRFS_IOC_INO_LOOKUP-setsockopt$netlink_NETLINK_BROADCAST_ERROR-ioctl$ifreq_SIOCGIFINDEX_batadv_hard-ioctl$sock_ipv4_tunnel_SIOCCHGTUNNEL-syz_genetlink_get_family_id$ipvs-sendmsg$IPVS_CMD_SET_INFO-syz_open_dev$tty20-getpgid-ptrace$ARCH_SHSTK_UNLOCK-setsockopt$inet6_IPV6_DSTOPTS-sendmmsg$inet6-preadv-shmget
```
- VM connection issues: 18 occurrences
- Latest: `05:50:05 candidates=-40 corpus=15201 coverage=114275 exec total=5612398 (436/sec) pending=83 reproducing=1 mode=FOCUS[PROBE:ebpf-uaf:socket$nl_generic-getsockopt$netlink-socket$inet6-sendmmsg$inet6]`

### AI Analytics Page
- /ai/analytics page: accessible

### Strategy Status
- Strategy: timestamp:2026-02-12T05:22:27.320612585+09:00, weights:10, seeds:5, focus_targets:3

---


---
## Verification Complete
All rounds finished at 2026-02-12 06:20:12. Syzkaller continues running.

### Overall Summary

- **Total crash groups**: 9
- **AI-triaged crashes**: 6
- **Total AI cost**: USD 1.0344
- **Log lines**: 339284
- **Focus mode triggers**: 67
- **AI batch runs**: 0
0
- **eBPF related logs**: 334341

- **Issues documented**: 0
0

