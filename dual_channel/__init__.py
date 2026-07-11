"""Two-channel (data-plane / control-plane) reference architecture.

Untrusted content and trusted instructions travel through two separate
services — deployable on different ports, hosts, or networks. The data plane
can only wrap content into signed inert blocks; the control plane accepts
data only when it carries the data plane's signature, and takes instructions
only from its own authenticated channel. See docs/DUAL_CHANNEL.md.
"""
