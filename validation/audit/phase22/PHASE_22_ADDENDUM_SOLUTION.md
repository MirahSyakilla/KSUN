# Phase 22 Addendum: Detector Findings and Mitigation

## Scope

This addendum excludes the Linux 4.19 audit by explicit request. It covers the
5.4.302 lisa device and the exported `vdinfos-20260915-1059.json` evidence.

No named detector application was launched or automated during this addendum:

- `ru.vd171.vdinfos`
- `com.juanma0511.rootdetector.debug`
- `com.xff.launch`
- `com.eltavine.duckdetector`
- any other detector package

The only app-context checks used for the port mitigation were neutral shell
probes executed under an untrusted app UID. Manual validation of the installed
detector applications remains outstanding and must be performed by the user.

## Findings

### VD Infos JSON

The JSON SHA-256 is:

```text
92f26ab719c2b274723297c898a98891d8cbefdbeb9959b9747b89c5ab882fc2
```

The three `MISMATCH` verdicts are:

| Entry | Classification | Owner |
|---|---|---|
| `set:adb_enabled` | Real HMA per-app settings virtualization escape on selection/appended query paths. Getter/call/bulk paths returned the virtual `0`, while some provider query paths exposed canonical `1`. | HMA/SettingsProvider policy, not KernelSU kernel code |
| `set:block_untrusted_touches` | Store-specific values: Global `0`, Secure/System `2`. This is not evidence that the three stores are interchangeable or that a root-state value leaked. | Android settings policy/framework |
| `spoof:adb_enabled` | Duplicate aggregate symptom of `set:adb_enabled`, not a separate defect. | Same as `set:adb_enabled` |

No KernelSU patch is justified for these entries. Do not duplicate `adb_enabled`
into deprecated Settings stores, use `resetprop` for database state, or force
`block_untrusted_touches` stores equal without proving the framework consumer's
canonical store.

### VPN and bindhosts

The observed `NetworkInfo` VPN record was inactive: current evidence has
`TRANSPORT_VPN=false`, no active tunnel interface or VPN route, and active
networks marked non-VPN. `bindhosts` is a hosts-file/module redirection feature;
it does not create an active `NetworkAgent`, VPN transport, tunnel interface, or
VPN route.

No VPN or bindhosts concealment change was made. A detector should require an
active `NetworkCapabilities.TRANSPORT_VPN` network and corroborate interface,
address, route, DNS/proxy, and per-UID selection before reporting an active VPN.

### JDWP and adbd socket observations

`@jdwp-control` and `libadbconnection*` are normal Android ART/adbd plumbing.
`/dev/socket/adbd` is intentionally protected by DAC and SELinux; ordinary-app
`EACCES` is the expected boundary. These surfaces were not hidden or weakened.

The actual configuration-specific exposure is root `adbd`:

```text
adbd: UID 0, context u:r:ksu:s0
listener: wildcard TCP port 7777, dual-stack behavior
owner: /data/adb/service.d/adbd.sh
```

### Android version consistency

The framework/API/attestation side reports Android 16/API 36, while the ROM
fingerprint and display identity retain an Android 14 `:14/UKQ1.240624.001`
token. This is a ROM/build-property provenance mismatch. It cannot be safely
fixed by changing `uname`, `CONFIG_LOCALVERSION`, KernelSU property readers, or
one hand-edited fingerprint. The proper owner is the ROM build/property
generation pipeline using one canonical signed release manifest.

## Port Mitigation

The requested defense-in-depth guard is installed at:

```text
/data/adb/service.d/ksu-app-port-guard.sh
```

The source/evidence copy is:

```text
validation/audit/phase22/adb-local-port-guard.sh
```

The currently installed guard is root-owned, mode `0755`, and reconciles IPv4
and IPv6 `OUTPUT` rules every 15 seconds. The repository copy is an audit
source artifact; deployment ownership remains `/data/adb/service.d` and must be
bound to the device's service owner before release. The tightened source uses a
dedicated chain and derives per-user app/isolated UID ranges instead of one
global high-UID range. It matches:

- local delivery through `lo`;
- TCP ports `5555` and `7777`;
- per-user Android app and isolated UID ranges;
- `REJECT --reject-with tcp-reset`.

It intentionally does not match:

- inbound TCP ADB;
- root or shell UID traffic;
- USB ADB;
- JDWP sockets;
- unrelated remote hosts using destination port 5555/7777.

The rule is not a replacement for disabling root TCP ADB. The external keeper
still starts root `adbd`; the guard only closes the local app-originated connect
oracle while retaining the administrative TCP transport.

## Device Evidence

Before reboot, neutral app UID `10310` received closed-port failures for:

```text
127.0.0.1:7777
::1:7777
```

Root and shell connections remained successful. The active TCP ADB transport
also remained successful.

After reboot:

```text
kernel: 5.4.302-g98391209
boot_completed: 1
SELinux: Enforcing
guard process: /data/adb/service.d/ksu-app-port-guard.sh
```

Neutral app UID `10302` was rejected on:

```text
127.0.0.1:7777
::1:7777
192.168.0.183:7777
```

The TCP ADB transport remained reachable. The rules were present in both
`iptables-save` and `ip6tables-save` for ports `5555` and `7777`.

The deployed `KSU_ADB_LOCAL` chain contained the per-user app and isolated
ranges `10000-19999` and `99000-99999` in both address families.

The source script installed on the tested device had SHA-256:

```text
be5bcc72cbe1d73ba4dec1c5147244c8fb4e3e7914a41a183793e629b0d63129
```

The tested device-side pathname hide was also enabled with:

```text
susfs add_sus_path_loop /dev/socket/adbd
```

Root continued to see `/dev/socket/adbd`. The genuine neutral
`u:r:untrusted_app` harness observed:

```text
PATH_STAT=STAT_FAIL errno=2(No such file or directory)
OPEN_path=FAIL errno=2(No such file or directory)
```

This is the required `ENOENT` result. The socket's DAC mode, owner, and
`adbd_socket` SELinux label were not changed. The persistent configuration
owner is BRENE's `custom_sus_path_loop.txt`, which is consumed by its existing
boot-completed SUSFS path loader. The corresponding source entry is committed
in the BRENE repository.

## Limitations

1. The guard is defense-in-depth. The cleanest security reduction remains
   disabling KernelSU `adb_root` and removing the persistent TCP keeper when
   root/TCP ADB is not required.
2. `-o lo` covers the tested local-address routes. If a future VPN or policy
   route sends local-address traffic through another interface, the guard must
   be extended with explicit current local-address rules.
3. `netd` may restore or replace firewall state. The reconciliation loop handles
   ordinary removal but is not a formal netd policy owner.
4. The guard source requires same-boot validation of the dedicated chain,
   per-user ranges, command compatibility, and rule presence after netd
   replacement before it is treated as a release artifact.
5. Manual validation of the pre-existing detector applications remains required
   and was deliberately not automated.
6. Existing Phase 22 NoMount/VFS/procfs/manifest blockers remain open; this
   addendum does not claim full security closure.

## Final Status

The port-7777 local non-root connect oracle is mitigated and survives one clean
reboot in the tested state. The VD Infos, VPN, JDWP, and Android build-identity
findings are correctly classified and assigned to their actual owners rather
than masked in the hookless kernel.

The overall Phase 22 security verdict remains **BLOCKED**, because the broader
Phase 22 acceptance criteria still include previously confirmed NoMount/VFS,
procfs, generated-manifest, and image-provenance blockers, and because manual
validation of the installed detector applications has not been performed.
