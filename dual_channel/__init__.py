"""Two-channel (data-plane / control-plane) reference architecture.

Untrusted content and trusted instructions travel through two separate
services — deployable on different ports, hosts, or networks. The data plane
can only wrap content into signed inert blocks; the control plane accepts
data only when it carries the data plane's signature, and takes instructions
only from its own authenticated channel.

The planes use Ed25519 for true cryptographic role separation: the data
plane holds the private (signing) key, the control plane holds only the
public (verification) key and is cryptographically unable to forge bands.
Keys resolve through the pluggable secret provider (SECRETS_BACKEND) with no
development fallback — the services refuse to start without real keys.
See docs/DUAL_CHANNEL.md.
"""

DATA_PLANE_KEY_ID = "data-plane"
DATA_PLANE_ISSUER = "data-plane"
