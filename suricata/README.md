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

**`sid:9100006` and `sid:9100008` are different.** They are generic EtherHiding analytics —
respectively TLS SNI to a set of known public EVM RPC providers, and cleartext JSON-RPC
`eth_call` over HTTP. They are the most transferable rules in the set and also the noisiest:
public RPCs are dual-use and these fire on any host legitimately running crypto tooling.
Deploy them as hunting or low-priority analytics, ideally correlated in the SIEM against
hosts with no other crypto or wallet activity. **Do not deploy them inline as blocks.**

The C2 rules assume cleartext WebSocket on TCP/3847, which is what this build used. A
TLS-wrapped variant would evade the content matches; TLS SNI or JA4 would be where to
extend coverage.

The provider list in `sid:9100006` is a starting point, not exhaustive — add the RPC
providers you actually see in your environment.
