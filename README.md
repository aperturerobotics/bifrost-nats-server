# NATS.io V2.0

## <img src="logos/nats-server.png" width="300">

----

[NATS](https://nats.io) is a simple, secure and performant communications system for digital systems, services and devices. NATS is part of the Cloud Native Computing Foundation ([CNCF](https://cncf.io)). NATS has over [30 client language implementations](https://nats.io/download/), and its server can run on-premise, in the cloud, at the edge, and even on a Raspberry Pi. NATS can secure and simplify design and operation of modern distributed systems.

This is the Aperture Robotics fork which adds a minimal patchset exposing the
inner server constructors to outside api consumers, so that we can construct the
server with a keypair created outside of Nats.

This version keeps the server as a library rather than a daemon.

## Significant Differences from Upstream

This is the Aperture Robotics Nats 2.0 fork, intended for integration with other
system components. To this end, connection management, reconnections,
encapsulated protocols (websocket), log rotation, IP address / URLs, are all
managed by code that does not live in this repo.

 - connection + tls: caller manages this and pass authenticated conns
 - authentication: managed by passing pre-authenticated conns
 - authorization: managed by Nats, without account expiration
   - all keys that can connect as per the caller are allowed
   - communication between accounts is controlled the usual way in NATS
   - expiration or removal of accounts or account sessions is removed 
 - tests: completely removed, mitigated by: 
   - upstream is tested
   - test downstream in e2e and integration tests
 - websocket: completely removed
 - configuration file syntax: completely removed (may be re-added as a package)
 - config reload: will be re-added eventually
 - connection management: no soliciting, route establishment gossip, conn URLs
   - nats does not care about IP/host/URL anymore

## License

Unless otherwise noted, the NATS source files are distributed
under the Apache Version 2.0 license found in the LICENSE file.

The Aperture changes list, as per the Aperture 2.0 license, are disclosed along
with the original license with any derived software binaries.
