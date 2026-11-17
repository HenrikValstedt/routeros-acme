# Local DNS records — design note

Idea: when a device gets a certificate, the app can also create the matching DNS record on
the routers that serve DNS to the LAN, so `https://gw.example.com` works inside the network
without a certificate warning. A plain IP address doesn't work well with TLS: a certificate is
for a *name*, and Let's Encrypt can't issue one for a private LAN address at all.

Status: **built on the dev branch** (not released). Code in `localdns.go`; the DNS tab, the
"Local DNS record" section in the device dialog and "Add manual device" in the UI. Tested with
unit tests (`localdns_plan_test.go`), the real-router test `TestRealRouterOSLocalDNS`, and an
end-to-end run against a CHR: records written and answered (A + AAAA), a hand-made record
reported as a conflict and left alone, the record following an address change, idempotent
re-checks, unticking a server, removing a device, removing a DNS server.

## Decisions so far (product owner)

- **One device or service per certificate is the normal case.** Wildcard is an option, not
  the default.
- **Several addresses per name** (e.g. one per VLAN, and IPv6) must be possible.
- **The record follows the device:** when its address changes, the record is updated.
- **A DNS name at enrollment:** if the device was enrolled by FQDN, that's the suggested name.
- **Docs must say:** clients that use their own DNS (secure DNS / DoH in browsers, some
  phones, hard-coded resolvers) don't see the router's records. Don't forget this.

## Design rules (agreed)

1. The app keeps reaching devices by their stored address, never through the records it
   manages, so a broken DNS router can't cut the app off.
2. Never change or remove a record the app didn't create. Records it did create are
   recognisable by a fixed comment (like the certificates' name format).
3. Choose which addresses go in the record; suggest the management address.
4. Follow address changes: read the device's own addresses at each check.
5. Short TTL (5 min), so changes reach clients quickly.
6. Status per DNS router (record in place / failed), with retries, like deploys.
7. Marking a device as a DNS server is a sensitive change: admin + fresh 2FA.
8. Records are removed with the device (and when the option is turned off).

## Test results (RouterOS 7.25.1, `TestRealRouterOSLocalDNS` + manual tests)

**Works with the existing restricted service account** (api, read, write; no new rights):
- add / set / remove / print on `/ip/dns/static` over api-ssl;
- several A records plus AAAA for one name; all are answered;
- `ttl=5m` is honoured; names are case-insensitive;
- an exact duplicate is refused with `entry already exists` (safe to retry);
- records are found by comment, and records made by others are visible;
- `/ip/address` and `/ipv6/address` can be read (includes `dynamic=true` for DHCP addresses,
  plus loopback and link-local, which the UI should hide).

**DoH:** a router whose upstream is DoH (`use-doh-server`) still answers its static records
locally. A static record also overrides a public name for clients that use the router
(split-horizon) — what we want.

**Traps found:**
- **RouterOS merges, it doesn't refuse.** If someone already has an A record for the name,
  our records are added next to it and clients get both addresses. The app must check for
  records by others *before* adding, and show a conflict instead.
- **A CNAME by someone else wins:** our A record for that name is silently ignored.
  Also a conflict.
- **Wildcards shadow everything under them.** Both `match-subdomain=yes` and `regexp=`
  records answer for every name below them, *including names that have their own exact
  record*, whatever the order in the list. One wildcard record for `*.example.com` would
  override every device's own record (and hand-made ones) under `example.com`.

## Consequence for the wildcard option

A wildcard *certificate* doesn't need a wildcard *DNS record*. **Decided (2026-11-17):**
records are always exact names (the device's DNS name, chosen at enrollment or on the
device), also when the certificate is a wildcard. A wildcard DNS record is only offered with
a clear warning, and only if no other records exist under it.

## Open questions (all answered)

- ~~Which routers are DNS servers?~~ **Decided (2026-11-17):** a separate **DNS servers** tab.
  There you either point to a device that's already enrolled, or add a new one (the same
  enrollment, but the device doesn't need a certificate of its own).
- ~~Several DNS routers?~~ **Decided (2026-11-17):** records go to **all** DNS servers by
  default; the setup dialog for a device's record lets you untick servers it shouldn't go to.
  Setups with a primary that syncs its records to the resolvers (like the product owner's:
  a non-resolving primary, synced every 5 minutes) simply add only the primary as a DNS
  server. Worth a line in the docs: then a change reaches clients within sync interval + TTL
  (about 10 minutes there), and the resolvers shouldn't be added as DNS servers too, because
  the synced copies carry the app's comment and would look like the app's own records.
- ~~Address source?~~ **Decided (2026-11-17):** the dialog lists the device's addresses with
  their interface names (read live from the device, IPv4 and IPv6; loopback and link-local
  hidden, DHCP addresses marked), and several can be ticked. The choice is stored per
  interface and family, so when the address on that interface changes (e.g. DHCP), the
  record follows.
- ~~Devices without a certificate?~~ **Decided (2026-11-17):**
  - **MikroTik devices:** the suggested DNS name is the device's name (the FQDN it was
    enrolled with when there is one), always editable. Proposal for a bare name like `sw03`:
    add the domain of its certificate (`sw03.example.com`).
  - **Non-MikroTik devices (NAS, printer, server) are in scope, managed manually:** a
    "manual device" with no enrollment and no deploy. It can have a certificate (issued and
    renewed as usual, installed by the user through Export) and a DNS record with addresses
    typed in. The app can't read or follow its addresses, so changes are made by hand. Ties
    in with the open point "automatic fetching of renewed certificates by other machines",
    which would remove the manual re-export.
