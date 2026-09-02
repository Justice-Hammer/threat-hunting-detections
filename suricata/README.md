# suricata

TLP:CLEAR Suricata rules. Local SID block **9100000-9100099**; renumber to fit your
own reserved range before deploying.

| File | Family | SIDs |
|---|---|---|
| `componenttask33.rules` | ComponentTask33 (MSI loader → Node.js agent) | 9100001-9100008 |

## Deploy

```bash
cp suricata/componenttask33.rules /etc/suricata/rules/
suricata -T -c /etc/suricata/suricata.yaml   # test config before reload
```

## PCAP-validated

These rules were rewritten against a real detonation capture (2026-08-27), which
corrected two things static analysis got wrong:

- **Agent→C2 WebSocket data frames are RFC6455-masked.** The `register` and `heartbeat`
  JSON is therefore *not* content-matchable at the network layer. Detection keys on the
  plaintext upgrade handshake (`sid:9100001`) and the server banner (`sid:9100002`)
  instead. Matching frame JSON needs a WS-terminating proxy or a host sensor.
- **The `eth_call` RPC is HTTPS.** Its body is encrypted, so `sid:9100005` matches TLS
  SNI rather than the request body.

Rules written against the pre-capture assumptions would not have fired at all.

## Tuning

`sid:9100001`-`9100005` and `9100007` are specific to this family and are safe to alert on.

That classification was re-checked on 2026-09-02, when `sid:9100001` lost its destination-port
pin and its false-positive surface widened from one port to all ports. It still holds. The rule
requires a `GET`, an `Upgrade: websocket` header and an `X-Agent-Token` header in the same
client request, and `X-Agent-Token` is a bespoke header name with no legitimate use we are
aware of. If your environment has an application that does use it, pin the rule back to a port
list locally rather than dropping it.

**`sid:9100006` and `sid:9100008` are different.** They are generic EtherHiding analytics:
respectively TLS SNI to a set of known public EVM RPC providers, and cleartext JSON-RPC
`eth_call` over HTTP. They are the most transferable rules in the set and also the noisiest:
public RPCs are dual-use and these fire on any host legitimately running crypto tooling.
Deploy them as hunting or low-priority analytics, ideally correlated in the SIEM against
hosts with no other crypto or wallet activity. **Do not deploy them inline as blocks.**

The C2 rules originally assumed cleartext WebSocket on TCP/3847, which is what the first
build used. On 2026-08-31 the operator rotated panel domain and port twice within sixteen
minutes, which would have silenced both rules. `sid:9100001` is now portless, because the
`X-Agent-Token` header on a WebSocket upgrade is selective enough by itself. `sid:9100002`
keeps a port list of the three observed values, because the Express banner alone is far too
common to run portless. Expect to extend that list.

Every C2 domain observed so far resolves to the same address, so a rule keyed on the address
survives rotations that a domain or port rule does not. A TLS-wrapped variant would still
evade the content matches; TLS SNI or JA4 is where to extend coverage.

The provider list in `sid:9100006` is a starting point, not exhaustive. Add the RPC
providers you actually see in your environment.
