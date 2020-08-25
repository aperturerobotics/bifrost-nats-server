module github.com/nats-io/nats.go

go 1.14

// aperture: use aperture-2.0 branch of fork
replace github.com/nats-io/nats-server/v2 => github.com/aperturerobotics/bifrost-nats-server/v2 v2.0.0-20200728011410-af6fb29263b2 // aperture-2.0

// aperture: use protobuf 1.3.x based fork for compatibility
replace github.com/golang/protobuf => github.com/aperturerobotics/go-protobuf-1.3.x v0.0.0-20200706003739-05fb54d407a9 // aperture-1.3.x

require (
	github.com/golang/protobuf v1.4.2
	github.com/nats-io/nats-server/v2 v2.1.8-0.20200617224755-fa744fdcdaa3
	github.com/nats-io/nkeys v0.2.0
	github.com/nats-io/nuid v1.0.1
)
