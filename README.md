# NATS.io V2.0

## <img src="logos/nats-server.png" width="300">

----

[NATS](https://nats.io) is a simple, secure and performant communications system for digital systems, services and devices. NATS is part of the Cloud Native Computing Foundation ([CNCF](https://cncf.io)). NATS has over [30 client language implementations](https://nats.io/download/), and its server can run on-premise, in the cloud, at the edge, and even on a Raspberry Pi. NATS can secure and simplify design and operation of modern distributed systems.

This is the Aperture Robotics fork which adds a minimal patchset exposing the
inner server constructors to outside api consumers, so that we can construct the
server with a keypair created outside of Nats.

## License

Unless otherwise noted, the NATS source files are distributed
under the Apache Version 2.0 license found in the LICENSE file.
