# Threat model: authorization + indirect prompt injection

## Trust boundaries

- **Identity:** JWT subject and tenant claims. Callers cannot self-assert another user.
- **Policy:** SpiceDB is the source of truth. Unavailable SpiceDB fails closed.
- **Retrieval:** Unauthorized chunks must not enter generator or tool arguments (structural noninterference).
- **Untrusted data:** Retrieved chunk text is always taint=`untrusted`.

## Adversary

A tenant user or document author who can insert text into documents they are allowed to write, or who issues queries intended to surface another tenant's chunks.

## Attack families

1. Allowed poison (XPIA on authorized docs)
2. Forbidden high-rank bait
3. Cross-document exfiltration via injected instructions
4. Stale ACL / revoked access
5. Confused-deputy tool call (`send_email`)
6. Adaptive/paraphrased injection
7. Cross-turn accumulation after permission change

## Evaluation protocol

Score structural exposure and behavioral leakage separately. Canaries and forbidden markers are unique per tenant. Tool ASR is an authorization decision, not a substring in prose. Report Wilson intervals.
