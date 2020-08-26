// Copyright 2012-2020 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"sync/atomic"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/sirupsen/logrus"
)

var allowUnknownTopLevelField = int32(0)

// NoErrOnUnknownFields can be used to change the behavior the processing
// of a configuration file. By default, an error is reported if unknown
// fields are found. If `noError` is set to true, no error will be reported
// if top-level unknown fields are found.
func NoErrOnUnknownFields(noError bool) {
	var val int32
	if noError {
		val = int32(1)
	}
	atomic.StoreInt32(&allowUnknownTopLevelField, val)
}

// ClusterOpts are options for clusters.
// NOTE: This structure is no longer used for monitoring endpoints
// and json tags are deprecated and may be removed in the future.
type ClusterOpts struct {
	Name           string            `json:"-"`
	Host           string            `json:"addr,omitempty"`
	Port           int               `json:"cluster_port,omitempty"`
	Username       string            `json:"-"`
	Password       string            `json:"-"`
	AuthTimeout    float64           `json:"auth_timeout,omitempty"`
	Permissions    *RoutePermissions `json:"-"`
	ListenStr      string            `json:"-"`
	Advertise      string            `json:"-"`
	NoAdvertise    bool              `json:"-"`
	ConnectRetries int               `json:"-"`
}

// GatewayOpts are options for gateways.
// NOTE: This structure is no longer used for monitoring endpoints
// and json tags are deprecated and may be removed in the future.
type GatewayOpts struct {
	Name           string               `json:"name"`
	Username       string               `json:"-"`
	Password       string               `json:"-"`
	AuthTimeout    float64              `json:"auth_timeout,omitempty"`
	ConnectRetries int                  `json:"connect_retries,omitempty"`
	Gateways       []*RemoteGatewayOpts `json:"gateways,omitempty"`
	RejectUnknown  bool                 `json:"reject_unknown,omitempty"`
}

// RemoteGatewayOpts are options for connecting to a remote gateway
// NOTE: This structure is no longer used for monitoring endpoints
// and json tags are deprecated and may be removed in the future.
type RemoteGatewayOpts struct {
	Name string `json:"name"`
}

// LeafNodeOpts are options for a given server to accept leaf node connections and/or connect to a remote cluster.
type LeafNodeOpts struct {
	Username          string        `json:"-"`
	Password          string        `json:"-"`
	Account           string        `json:"-"`
	Users             []*User       `json:"-"`
	AuthTimeout       float64       `json:"auth_timeout,omitempty"`
	ReconnectInterval time.Duration `json:"-"`

	// For solicited connections to other clusters/superclusters.
	Remotes []*RemoteLeafOpts `json:"remotes,omitempty"`
}

// RemoteLeafOpts are options for connecting to a remote server as a leaf node.
type RemoteLeafOpts struct {
	Name         string   `json:"name"`
	LocalAccount string   `json:"local_account,omitempty"`
	Credentials  string   `json:"-"`
	Hub          bool     `json:"hub,omitempty"`
	DenyImports  []string `json:"-"`
	DenyExports  []string `json:"-"`
}

// Options block for nats-server.
// NOTE: This structure is no longer used for monitoring endpoints
// and json tags are deprecated and may be removed in the future.
type Options struct {
	ServerName            string        `json:"server_name"`
	Trace                 bool          `json:"-"`
	Debug                 bool          `json:"-"`
	TraceVerbose          bool          `json:"-"`
	NoSigs                bool          `json:"-"`
	NoSublistCache        bool          `json:"-"`
	NoHeaderSupport       bool          `json:"-"`
	DisableShortFirstPing bool          `json:"-"`
	Logtime               bool          `json:"-"`
	MaxConn               int           `json:"max_connections"`
	MaxSubs               int           `json:"max_subscriptions,omitempty"`
	Nkeys                 []*NkeyUser   `json:"-"`
	Users                 []*User       `json:"-"`
	Accounts              []*Account    `json:"-"`
	NoAuthUser            string        `json:"-"`
	SystemAccount         string        `json:"-"`
	NoSystemAccount       bool          `json:"-"`
	AllowNewAccounts      bool          `json:"-"`
	Username              string        `json:"-"`
	Password              string        `json:"-"`
	Authorization         string        `json:"-"`
	PingInterval          time.Duration `json:"ping_interval"`
	MaxPingsOut           int           `json:"ping_max"`
	AuthTimeout           float64       `json:"auth_timeout"`
	MaxControlLine        int32         `json:"max_control_line"`
	MaxPayload            int32         `json:"max_payload"`
	MaxPending            int64         `json:"max_pending"`
	Cluster               ClusterOpts   `json:"cluster,omitempty"`
	Gateway               GatewayOpts   `json:"gateway,omitempty"`
	LeafNode              LeafNodeOpts  `json:"leaf,omitempty"`
	JetStream             bool          `json:"jetstream"`
	JetStreamMaxMemory    int64         `json:"-"`
	JetStreamMaxStore     int64         `json:"-"`
	StoreDir              string        `json:"-"`
	ProfPort              int           `json:"-"`
	PidFile               string        `json:"-"`
	PortsFileDir          string        `json:"-"`
	LogFile               string        `json:"-"`
	LogSizeLimit          int64         `json:"-"`
	Syslog                bool          `json:"-"`
	RemoteSyslog          string        `json:"-"`
	RoutePeers            []string      `json:"-"`
	WriteDeadline         time.Duration `json:"-"`
	MaxClosedClients      int           `json:"-"`
	LameDuckDuration      time.Duration `json:"-"`
	LameDuckGracePeriod   time.Duration `json:"-"`

	// MaxTracedMsgLen is the maximum printable length for traced messages.
	MaxTracedMsgLen int `json:"-"`

	// Operating a trusted NATS server
	TrustedKeys      []string              `json:"-"`
	TrustedOperators []*jwt.OperatorClaims `json:"-"`
	AccountResolver  AccountResolver       `json:"-"`
	resolverPreloads map[string]string

	CustomClientAuthentication Authentication `json:"-"`
	CustomRouterAuthentication Authentication `json:"-"`

	// ConnectErrorReports specifies the number of failed attempts
	// at which point server should report the failure of an initial
	// connection to a route, gateway or leaf node.
	// See DEFAULT_CONNECT_ERROR_REPORTS for default value.
	ConnectErrorReports int

	// ReconnectErrorReports is similar to ConnectErrorReports except
	// that this applies to reconnect events.
	ReconnectErrorReports int

	// Logger is the logger override to use
	Logger *logrus.Entry

	// private fields, used to know if bool options are explicitly
	// defined in config and/or command line params.
	inConfig  map[string]bool
	inCmdLine map[string]bool

	// private fields, used for testing
	gatewaysSolicitDelay time.Duration
	routeProto           int
}

// Clone performs a deep copy of the Options struct, returning a new clone
// with all values copied.
func (o *Options) Clone() *Options {
	if o == nil {
		return nil
	}
	clone := &Options{}
	*clone = *o
	if o.Users != nil {
		clone.Users = make([]*User, len(o.Users))
		for i, user := range o.Users {
			clone.Users[i] = user.clone()
		}
	}
	if o.Nkeys != nil {
		clone.Nkeys = make([]*NkeyUser, len(o.Nkeys))
		for i, nkey := range o.Nkeys {
			clone.Nkeys[i] = nkey.clone()
		}
	}

	if len(o.RoutePeers) != 0 {
		clone.RoutePeers = make([]string, len(o.RoutePeers))
		copy(clone.RoutePeers, o.RoutePeers)
	}
	if len(o.Gateway.Gateways) > 0 {
		clone.Gateway.Gateways = make([]*RemoteGatewayOpts, len(o.Gateway.Gateways))
		for i, g := range o.Gateway.Gateways {
			clone.Gateway.Gateways[i] = g.clone()
		}
	}
	// FIXME(dlc) - clone leaf node stuff.
	return clone
}

// Configuration file authorization section.
type authorization struct {
	// Singles
	user  string
	pass  string
	token string
	acc   string
	// Multiple Nkeys/Users
	nkeys              []*NkeyUser
	users              []*User
	timeout            float64
	defaultPermissions *Permissions
}

var dynamicJSAccountLimits = &JetStreamAccountLimits{-1, -1, -1, -1}

// Sets cluster's permissions based on given pub/sub permissions,
// doing the appropriate translation.
func setClusterPermissions(opts *ClusterOpts, perms *Permissions) {
	// Import is whether or not we will send a SUB for interest to the other side.
	// Export is whether or not we will accept a SUB from the remote for a given subject.
	// Both only effect interest registration.
	// The parsing sets Import into Publish and Export into Subscribe, convert
	// accordingly.
	opts.Permissions = &RoutePermissions{
		Import: perms.Publish,
		Export: perms.Subscribe,
	}
}

// Temp structures to hold account import and export defintions since they need
// to be processed after being parsed.
type export struct {
	acc  *Account
	sub  string
	accs []string
	rt   ServiceRespType
	lat  *serviceLatency
	rthr time.Duration
}

type importStream struct {
	acc *Account
	an  string
	sub string
	pre string
}

type importService struct {
	acc   *Account
	an    string
	sub   string
	to    string
	share bool
}

// Checks if an account name is reserved.
func isReservedAccount(name string) bool {
	return name == globalAccountName
}

func setBaselineOptions(opts *Options) {
	// Setup non-standard Go defaults
	if opts.MaxConn == 0 {
		opts.MaxConn = DEFAULT_MAX_CONNECTIONS
	}
	if opts.PingInterval == 0 {
		opts.PingInterval = DEFAULT_PING_INTERVAL
	}
	if opts.MaxPingsOut == 0 {
		opts.MaxPingsOut = DEFAULT_PING_MAX_OUT
	}
	if opts.Cluster.AuthTimeout == 0 {
		opts.Cluster.AuthTimeout = float64(AUTH_TIMEOUT) / float64(time.Second)
	}
	if opts.LeafNode.AuthTimeout == 0 {
		opts.LeafNode.AuthTimeout = float64(AUTH_TIMEOUT) / float64(time.Second)
	}

	// Set this regardless of opts.LeafNode.Port
	if opts.LeafNode.ReconnectInterval == 0 {
		opts.LeafNode.ReconnectInterval = DEFAULT_LEAF_NODE_RECONNECT
	}

	if opts.MaxControlLine == 0 {
		opts.MaxControlLine = MAX_CONTROL_LINE_SIZE
	}
	if opts.MaxPayload == 0 {
		opts.MaxPayload = MAX_PAYLOAD_SIZE
	}
	if opts.MaxPending == 0 {
		opts.MaxPending = MAX_PENDING_SIZE
	}
	if opts.WriteDeadline == time.Duration(0) {
		opts.WriteDeadline = DEFAULT_FLUSH_DEADLINE
	}
	if opts.MaxClosedClients == 0 {
		opts.MaxClosedClients = DEFAULT_MAX_CLOSED_CLIENTS
	}
	if opts.LameDuckDuration == 0 {
		opts.LameDuckDuration = DEFAULT_LAME_DUCK_DURATION
	}
	if opts.LameDuckGracePeriod == 0 {
		opts.LameDuckGracePeriod = DEFAULT_LAME_DUCK_GRACE_PERIOD
	}
	if opts.Gateway.AuthTimeout == 0 {
		opts.Gateway.AuthTimeout = float64(AUTH_TIMEOUT) / float64(time.Second)
	}
	if opts.ConnectErrorReports == 0 {
		opts.ConnectErrorReports = DEFAULT_CONNECT_ERROR_REPORTS
	}
	if opts.ReconnectErrorReports == 0 {
		opts.ReconnectErrorReports = DEFAULT_RECONNECT_ERROR_REPORTS
	}
	// JetStream
	if opts.JetStreamMaxMemory == 0 {
		opts.JetStreamMaxMemory = -1
	}
	if opts.JetStreamMaxStore == 0 {
		opts.JetStreamMaxStore = -1
	}
	if opts.Logger == nil {
		l := logrus.New()
		l.SetLevel(logrus.DebugLevel)
		opts.Logger = logrus.NewEntry(l)
	}
}
