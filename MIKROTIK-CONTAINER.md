# Running routeros-acme on a MikroTik (RouterOS 7 container)

Steps marked *tested* ran on RouterOS 7.25.1 on a CHR (x86), an RB4011 (arm/v7) and a hAP be³ Media (arm64),
2026-11-16.

## Requirements
- RouterOS 7 on arm, arm64 or x86 (e.g. RB4011, RB5009, CCR2004, hAP ax³, CHR).
- About 20 MB of disk and a few MB of RAM. On devices with small flash, prefer a USB stick or disk
  (put `containers/...` paths below on it, e.g. `usb1/containers/...`).
- Physical access to the router once (step 2).

## 1. Install the container package (one reboot) — *tested*
```
/system/package/enable container
/system/package/apply-changes
```
Or in WebFig: **System → Packages → container → Enable → Apply Changes**.
If the router doesn't reboot, wait a few seconds and run `/system/package/apply-changes` again (seen on a hAP,
where the package first had to be downloaded).

**Tip — one reboot instead of two** (*tested* on RB4011): run only `/system/package/enable container` (without
`apply-changes`), then do step 2. Its power cut installs the package as well.

## 2. Turn on container mode (physical, one reboot) — *tested*
Check first: `/system/device-mode/print`. If it already says `container: yes`, skip this step. Some devices ship
that way, e.g. the hAP be³ Media in device-mode `rose` (seen on two units, 2026-11-16).
```
/system/device-mode/update container=yes
```
Within 5 minutes **pull the power** for ~5 seconds, or press the reset button **briefly** (never hold it).
A reboot from WebFig/WinBox does **not** confirm it (tested on 7.25.1). Check afterwards:
`/system/device-mode/print` → `container: yes`.

## 3. Network: own interface, internet access, port forward — *tested*
```
/interface/veth/add name=veth-acme address=172.31.255.2/30 gateway=172.31.255.1
/interface/bridge/add name=containers
/interface/bridge/port/add bridge=containers interface=veth-acme
/ip/address/add address=172.31.255.1/30 interface=containers
/ip/firewall/nat/add chain=srcnat src-address=172.31.255.0/30 action=masquerade comment="routeros-acme: outbound"
/ip/firewall/nat/add chain=dstnat dst-address=<ROUTER-IP> protocol=tcp dst-port=8080 action=dst-nat to-addresses=172.31.255.2 to-ports=8080 comment="routeros-acme: web UI"
```
Choose a port that isn't used on the router and a `/30` that isn't used in your network. If the router has a
firewall, allow the port only from your admin network.

## 4. Download and start the container — *tested*
```
/container/config/set registry-url=https://ghcr.io tmpdir=containers/tmp
/container/mounts/add list=acme-data src=containers/routeros-acme-data dst=/data
/container/envs/add list=acme key=TZ value=Europe/Stockholm
/container/add name=routeros-acme remote-image=henrikvalstedt/routeros-acme:latest interface=veth-acme root-dir=containers/routeros-acme mountlists=acme-data envlists=acme memory-high=268435456 start-on-boot=yes logging=yes
```
**If the router uses only DNS-over-HTTPS** (`/ip/dns/print` shows `servers:` empty and a `use-doh-server`), the
container won't start ("no default dns servers"). Give it the router itself as DNS server (*tested* on hAP be³):
```
/container/set [find name=routeros-acme] dns=172.31.255.1
```
(The router must answer DNS: `/ip/dns/set allow-remote-requests=yes`, and its firewall must allow DNS from the container.)

Wait until `/container/print` shows it stopped (download and extract finished), then:
```
/container/start [find name=routeros-acme]
```

## 5. First login — *tested*
```
/log print where topics~"container"
```
The log shows `Setup code: …`. Open `http://<ROUTER-IP>:8080` and create the admin account.

Your data (accounts, certificates, keys) lives in the mount `containers/routeros-acme-data`, not inside the
container, so it survives `/container/stop` + `/container/start` and router reboots (*tested*).

## Notes
- `latest` follows releases; use a version tag (e.g. `:1.6.5`) to decide upgrades yourself.
- The image's hardening works on RouterOS too: the app drops to an unprivileged user (*tested*).
- RouterOS 7.25 syntax: mounts and envs use `list=` (older guides with `name=` fail).
- After a RouterOS upgrade the container package must match the RouterOS version (the normal upgrade handles it).
- `memory-high` (256 MiB above) is a soft cap so the app can never starve RouterOS.
- Measured: about 15 MiB on flash, 2.5–5 MiB RAM, CPU near 0% when idle (RB4011 and hAP be³ Media).
  `/container/print` may show a too small `container-size` on some devices; check free flash instead.
- Right after you add the dstnat rule it may show the flag `I` (invalid) for a moment; that clears by itself.

## Not tested yet
- **Upgrading the app** to a new image on the router (exact commands to be tried).
- **Managing the router the app runs on:** enroll host `172.31.255.1`; the router's SSH and api-ssl must accept
  connections from `172.31.255.0/30`.

## Removing it
```
/container/stop [find name=routeros-acme]
/container/remove [find name=routeros-acme]
/container/mounts/remove [find list=acme-data]
/container/envs/remove [find list=acme]
/ip/firewall/nat/remove [find comment~"routeros-acme:"]
/ip/address/remove [find interface=containers]
/interface/bridge/port/remove [find interface=veth-acme]
/interface/bridge/remove [find name=containers]
/interface/veth/remove [find name=veth-acme]
```
