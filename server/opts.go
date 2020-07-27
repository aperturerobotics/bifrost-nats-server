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
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/sirupsen/logrus"

	"github.com/nats-io/nats-server/v2/conf"
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
	Username       string            `json:"-"`
	Password       string            `json:"-"`
	AuthTimeout    float64           `json:"auth_timeout,omitempty"`
	Permissions    *RoutePermissions `json:"-"`
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

	// Not exported, for tests.
	sendQSubsBufSize int
}

// RemoteGatewayOpts are options for connecting to a remote gateway
// NOTE: This structure is no longer used for monitoring endpoints
// and json tags are deprecated and may be removed in the future.
type RemoteGatewayOpts struct {
	Name string `json:"name"`
}

// LeafNodeOpts are options for a given server to accept leaf node connections and/or connect to a remote cluster.
type LeafNodeOpts struct {
	Name              string        `json:"name,omitempty"`
	Username          string        `json:"-"`
	Password          string        `json:"-"`
	Account           string        `json:"-"`
	Users             []*User       `json:"-"`
	AuthTimeout       float64       `json:"auth_timeout,omitempty"`
	ReconnectInterval time.Duration `json:"-"`

	// For solicited connections to other clusters/superclusters.
	Remotes []*RemoteLeafOpts `json:"remotes,omitempty"`

	// Not exported, for tests.
	dialTimeout time.Duration
	connDelay   time.Duration
}

// RemoteLeafOpts are options for connecting to a remote server as a leaf node.
type RemoteLeafOpts struct {
	Name         string   `json:"name,omitempty"`
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
	ConfigFile            string        `json:"-"`
	ServerName            string        `json:"server_name"`
	Trace                 bool          `json:"-"`
	Debug                 bool          `json:"-"`
	TraceVerbose          bool          `json:"-"`
	NoLog                 bool          `json:"-"`
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
	HTTPBasePath          string        `json:"http_base_path"`
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

	// CheckConfig configuration file syntax test was successful and exit.
	CheckConfig bool `json:"-"`

	// Logger overrides the logger entry.
	Logger *logrus.Entry `json:"-"`

	// ConnectErrorReports specifies the number of failed attempts
	// at which point server should report the failure of an initial
	// connection to a route, gateway or leaf node.
	// See DEFAULT_CONNECT_ERROR_REPORTS for default value.
	ConnectErrorReports int

	// ReconnectErrorReports is similar to ConnectErrorReports except
	// that this applies to reconnect events.
	ReconnectErrorReports int

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

// ProcessConfigFile processes a configuration file.
// FIXME(dlc): A bit hacky
func ProcessConfigFile(configFile string) (*Options, error) {
	opts := &Options{}
	if err := opts.ProcessConfigFile(configFile); err != nil {
		// If only warnings then continue and return the options.
		if cerr, ok := err.(*processConfigErr); ok && len(cerr.Errors()) == 0 {
			return opts, nil
		}

		return nil, err
	}
	return opts, nil
}

// token is an item parsed from the configuration.
type token interface {
	Value() interface{}
	Line() int
	IsUsedVariable() bool
	SourceFile() string
	Position() int
}

// unwrapValue can be used to get the token and value from an item
// to be able to report the line number in case of an incorrect
// configuration.
// also stores the token in lastToken for use in convertPanicToError
func unwrapValue(v interface{}, lastToken *token) (token, interface{}) {
	switch tk := v.(type) {
	case token:
		if lastToken != nil {
			*lastToken = tk
		}
		return tk, tk.Value()
	default:
		return nil, v
	}
}

// use in defer to recover from panic and turn it into an error associated with last token
func convertPanicToErrorList(lastToken *token, errors *[]error) {
	// only recover if an error can be stored
	if errors == nil {
		return
	} else if err := recover(); err == nil {
		return
	} else if lastToken != nil && *lastToken != nil {
		*errors = append(*errors, &configErr{*lastToken, fmt.Sprint(err)})
	} else {
		*errors = append(*errors, fmt.Errorf("encountered panic without a token %v", err))
	}
}

// use in defer to recover from panic and turn it into an error associated with last token
func convertPanicToError(lastToken *token, e *error) {
	// only recover if an error can be stored
	if e == nil || *e != nil {
		return
	} else if err := recover(); err == nil {
		return
	} else if lastToken != nil && *lastToken != nil {
		*e = &configErr{*lastToken, fmt.Sprint(err)}
	} else {
		*e = fmt.Errorf("%v", err)
	}
}

// configureSystemAccount configures a system account
// if present in the configuration.
func configureSystemAccount(o *Options, m map[string]interface{}) (retErr error) {
	var lt token
	defer convertPanicToError(&lt, &retErr)
	configure := func(v interface{}) error {
		tk, v := unwrapValue(v, &lt)
		sa, ok := v.(string)
		if !ok {
			return &configErr{tk, "system account name must be a string"}
		}
		o.SystemAccount = sa
		return nil
	}

	if v, ok := m["system_account"]; ok {
		return configure(v)
	} else if v, ok := m["system"]; ok {
		return configure(v)
	}

	return nil
}

// ProcessConfigFile updates the Options structure with options
// present in the given configuration file.
// This version is convenient if one wants to set some default
// options and then override them with what is in the config file.
// For instance, this version allows you to do something such as:
//
// opts := &Options{Debug: true}
// opts.ProcessConfigFile(myConfigFile)
//
// If the config file contains "debug: false", after this call,
// opts.Debug would really be false. It would be impossible to
// achieve that with the non receiver ProcessConfigFile() version,
// since one would not know after the call if "debug" was not present
// or was present but set to false.
func (o *Options) ProcessConfigFile(configFile string) error {
	o.ConfigFile = configFile
	if configFile == "" {
		return nil
	}
	m, err := conf.ParseFileWithChecks(configFile)
	if err != nil {
		return err
	}
	// Collect all errors and warnings and report them all together.
	errors := make([]error, 0)
	warnings := make([]error, 0)

	// First check whether a system account has been defined,
	// as that is a condition for other features to be enabled.
	if err := configureSystemAccount(o, m); err != nil {
		errors = append(errors, err)
	}

	for k, v := range m {
		o.processConfigFileLine(k, v, &errors, &warnings)
	}

	if len(errors) > 0 || len(warnings) > 0 {
		return &processConfigErr{
			errors:   errors,
			warnings: warnings,
		}
	}

	return nil
}

func (o *Options) processConfigFileLine(k string, v interface{}, errors *[]error, warnings *[]error) {
	var lt token
	defer convertPanicToErrorList(&lt, errors)

	tk, v := unwrapValue(v, &lt)
	switch strings.ToLower(k) {
	case "server_name":
		o.ServerName = v.(string)
	case "debug":
		o.Debug = v.(bool)
		trackExplicitVal(o, &o.inConfig, "Debug", o.Debug)
	case "trace":
		o.Trace = v.(bool)
		trackExplicitVal(o, &o.inConfig, "Trace", o.Trace)
	case "trace_verbose":
		o.TraceVerbose = v.(bool)
		o.Trace = v.(bool)
		trackExplicitVal(o, &o.inConfig, "TraceVerbose", o.TraceVerbose)
		trackExplicitVal(o, &o.inConfig, "Trace", o.Trace)
	case "logtime":
		o.Logtime = v.(bool)
		trackExplicitVal(o, &o.inConfig, "Logtime", o.Logtime)
	case "disable_sublist_cache", "no_sublist_cache":
		o.NoSublistCache = v.(bool)
	case "accounts":
		err := parseAccounts(tk, o, errors, warnings)
		if err != nil {
			*errors = append(*errors, err)
			return
		}
	case "authorization":
		auth, err := parseAuthorization(tk, o, errors, warnings)
		if err != nil {
			*errors = append(*errors, err)
			return
		}

		o.Username = auth.user
		o.Password = auth.pass
		o.Authorization = auth.token
		if (auth.user != "" || auth.pass != "") && auth.token != "" {
			err := &configErr{tk, "Cannot have a user/pass and token"}
			*errors = append(*errors, err)
			return
		}
		o.AuthTimeout = auth.timeout
		// Check for multiple users defined
		if auth.users != nil {
			if auth.user != "" {
				err := &configErr{tk, "Can not have a single user/pass and a users array"}
				*errors = append(*errors, err)
				return
			}
			if auth.token != "" {
				err := &configErr{tk, "Can not have a token and a users array"}
				*errors = append(*errors, err)
				return
			}
			// Users may have been added from Accounts parsing, so do an append here
			o.Users = append(o.Users, auth.users...)
		}

		// Check for nkeys
		if auth.nkeys != nil {
			// NKeys may have been added from Accounts parsing, so do an append here
			o.Nkeys = append(o.Nkeys, auth.nkeys...)
		}
	case "http_base_path":
		o.HTTPBasePath = v.(string)
	case "cluster":
		err := parseCluster(tk, o, errors, warnings)
		if err != nil {
			*errors = append(*errors, err)
			return
		}
	case "gateway":
		if err := parseGateway(tk, o, errors, warnings); err != nil {
			*errors = append(*errors, err)
			return
		}
	case "leaf", "leafnodes":
		err := parseLeafNodes(tk, o, errors, warnings)
		if err != nil {
			*errors = append(*errors, err)
			return
		}
	case "jetstream":
		err := parseJetStream(tk, o, errors, warnings)
		if err != nil {
			*errors = append(*errors, err)
			return
		}
	case "max_control_line":
		if v.(int64) > 1<<31-1 {
			err := &configErr{tk, fmt.Sprintf("%s value is too big", k)}
			*errors = append(*errors, err)
			return
		}
		o.MaxControlLine = int32(v.(int64))
	case "max_payload":
		if v.(int64) > 1<<31-1 {
			err := &configErr{tk, fmt.Sprintf("%s value is too big", k)}
			*errors = append(*errors, err)
			return
		}
		o.MaxPayload = int32(v.(int64))
	case "max_pending":
		o.MaxPending = v.(int64)
	case "max_connections", "max_conn":
		o.MaxConn = int(v.(int64))
	case "max_traced_msg_len":
		o.MaxTracedMsgLen = int(v.(int64))
	case "max_subscriptions", "max_subs":
		o.MaxSubs = int(v.(int64))
	case "ping_interval":
		o.PingInterval = parseDuration("ping_interval", tk, v, errors, warnings)
	case "ping_max":
		o.MaxPingsOut = int(v.(int64))
	case "write_deadline":
		o.WriteDeadline = parseDuration("write_deadline", tk, v, errors, warnings)
	case "lame_duck_duration":
		dur, err := time.ParseDuration(v.(string))
		if err != nil {
			err := &configErr{tk, fmt.Sprintf("error parsing lame_duck_duration: %v", err)}
			*errors = append(*errors, err)
			return
		}
		if dur < 30*time.Second {
			err := &configErr{tk, fmt.Sprintf("invalid lame_duck_duration of %v, minimum is 30 seconds", dur)}
			*errors = append(*errors, err)
			return
		}
		o.LameDuckDuration = dur
	case "lame_duck_grace_period":
		dur, err := time.ParseDuration(v.(string))
		if err != nil {
			err := &configErr{tk, fmt.Sprintf("error parsing lame_duck_grace_period: %v", err)}
			*errors = append(*errors, err)
			return
		}
		if dur < 0 {
			err := &configErr{tk, "invalid lame_duck_grace_period, needs to be positive"}
			*errors = append(*errors, err)
			return
		}
		o.LameDuckGracePeriod = dur
	case "operator", "operators", "roots", "root", "root_operators", "root_operator":
		opFiles := []string{}
		switch v := v.(type) {
		case string:
			opFiles = append(opFiles, v)
		case []string:
			opFiles = append(opFiles, v...)
		default:
			err := &configErr{tk, fmt.Sprintf("error parsing operators: unsupported type %T", v)}
			*errors = append(*errors, err)
		}
		// Assume for now these are file names, but they can also be the JWT itself inline.
		o.TrustedOperators = make([]*jwt.OperatorClaims, 0, len(opFiles))
		for _, fname := range opFiles {
			opc, err := ReadOperatorJWT(fname)
			if err != nil {
				err := &configErr{tk, fmt.Sprintf("error parsing operator JWT: %v", err)}
				*errors = append(*errors, err)
				continue
			}
			o.TrustedOperators = append(o.TrustedOperators, opc)
		}
		if len(o.TrustedOperators) == 1 {
			// In case "resolver" is defined as well, it takes precedence
			if o.AccountResolver == nil {
				if accUrl, err := parseURL(o.TrustedOperators[0].AccountServerURL, "account resolver"); err == nil {
					// nsc automatically appends "/accounts" during nsc push
					o.AccountResolver, _ = NewURLAccResolver(accUrl.String() + "/accounts")
				}
			}
			// In case "system_account" is defined as well, it takes precedence
			if o.SystemAccount == "" {
				o.SystemAccount = o.TrustedOperators[0].SystemAccount
			}
		}
	case "resolver", "account_resolver", "accounts_resolver":
		switch v := v.(type) {
		case string:
			// "resolver" takes precedence over value obtained from "operator".
			// Clear so that parsing errors are not silently ignored.
			o.AccountResolver = nil
			memResolverRe := regexp.MustCompile(`(?i)(MEM|MEMORY)\s*`)
			resolverRe := regexp.MustCompile(`(?i)(?:URL){1}(?:\({1}\s*"?([^\s"]*)"?\s*\){1})?\s*`)
			if memResolverRe.MatchString(v) {
				o.AccountResolver = &MemAccResolver{}
			} else if items := resolverRe.FindStringSubmatch(v); len(items) == 2 {
				url := items[1]
				_, err := parseURL(url, "account resolver")
				if err != nil {
					*errors = append(*errors, &configErr{tk, err.Error()})
					return
				}
				if ur, err := NewURLAccResolver(url); err != nil {
					err := &configErr{tk, err.Error()}
					*errors = append(*errors, err)
					return
				} else {
					o.AccountResolver = ur
				}
			}
		default:
			err := &configErr{tk, fmt.Sprintf("error parsing operator resolver, wrong type %T", v)}
			*errors = append(*errors, err)
			return
		}
		if o.AccountResolver == nil {
			err := &configErr{tk, "error parsing account resolver, should be MEM or " +
				" URL(\"url\") or a map containing dir and type state=[FULL|CACHE])"}
			*errors = append(*errors, err)
		}
	case "resolver_preload":
		mp, ok := v.(map[string]interface{})
		if !ok {
			err := &configErr{tk, "preload should be a map of account_public_key:account_jwt"}
			*errors = append(*errors, err)
			return
		}
		o.resolverPreloads = make(map[string]string)
		for key, val := range mp {
			tk, val = unwrapValue(val, &lt)
			if jwtstr, ok := val.(string); !ok {
				err := &configErr{tk, "preload map value should be a string JWT"}
				*errors = append(*errors, err)
				continue
			} else {
				// Make sure this is a valid account JWT, that is a config error.
				// We will warn of expirations, etc later.
				if _, err := jwt.DecodeAccountClaims(jwtstr); err != nil {
					err := &configErr{tk, "invalid account JWT"}
					*errors = append(*errors, err)
					continue
				}
				o.resolverPreloads[key] = jwtstr
			}
		}
	case "no_auth_user":
		o.NoAuthUser = v.(string)
	case "system_account", "system":
		// Already processed at the beginning so we just skip them
		// to not treat them as unknown values.
		return
	case "no_system_account", "no_system", "no_sys_acc":
		o.NoSystemAccount = v.(bool)
	case "no_header_support":
		o.NoHeaderSupport = v.(bool)
	case "trusted", "trusted_keys":
		switch v := v.(type) {
		case string:
			o.TrustedKeys = []string{v}
		case []string:
			o.TrustedKeys = v
		case []interface{}:
			keys := make([]string, 0, len(v))
			for _, mv := range v {
				tk, mv = unwrapValue(mv, &lt)
				if key, ok := mv.(string); ok {
					keys = append(keys, key)
				} else {
					err := &configErr{tk, fmt.Sprintf("error parsing trusted: unsupported type in array %T", mv)}
					*errors = append(*errors, err)
					continue
				}
			}
			o.TrustedKeys = keys
		default:
			err := &configErr{tk, fmt.Sprintf("error parsing trusted: unsupported type %T", v)}
			*errors = append(*errors, err)
		}
		// Do a quick sanity check on keys
		/*
			for _, key := range o.TrustedKeys {
				if !nkeys.IsValidPublicOperatorKey(key) {
					err := &configErr{tk, fmt.Sprintf("trust key %q required to be a valid public operator nkey", key)}
					*errors = append(*errors, err)
				}
			}
		*/
	case "connect_error_reports":
		o.ConnectErrorReports = int(v.(int64))
	case "reconnect_error_reports":
		o.ReconnectErrorReports = int(v.(int64))
	default:
		if au := atomic.LoadInt32(&allowUnknownTopLevelField); au == 0 && !tk.IsUsedVariable() {
			err := &unknownConfigFieldErr{
				field: k,
				configErr: configErr{
					token: tk,
				},
			}
			*errors = append(*errors, err)
		}
	}
}

func parseDuration(field string, tk token, v interface{}, errors *[]error, warnings *[]error) time.Duration {
	if wd, ok := v.(string); ok {
		if dur, err := time.ParseDuration(wd); err != nil {
			err := &configErr{tk, fmt.Sprintf("error parsing %s: %v", field, err)}
			*errors = append(*errors, err)
			return 0
		} else {
			return dur
		}
	} else {
		// Backward compatible with old type, assume this is the
		// number of seconds.
		err := &configWarningErr{
			field: field,
			configErr: configErr{
				token:  tk,
				reason: field + " should be converted to a duration",
			},
		}
		*warnings = append(*warnings, err)
		return time.Duration(v.(int64)) * time.Second
	}
}

func trackExplicitVal(opts *Options, pm *map[string]bool, name string, val bool) {
	m := *pm
	if m == nil {
		m = make(map[string]bool)
		*pm = m
	}
	m[name] = val
}

// hostPort is simple struct to hold parsed listen/addr strings.
type hostPort struct {
	host string
	port int
}

// parseCluster will parse the cluster config.
func parseCluster(v interface{}, opts *Options, errors *[]error, warnings *[]error) error {
	var lt token
	defer convertPanicToErrorList(&lt, errors)

	tk, v := unwrapValue(v, &lt)
	cm, ok := v.(map[string]interface{})
	if !ok {
		return &configErr{tk, fmt.Sprintf("Expected map to define cluster, got %T", v)}
	}

	for mk, mv := range cm {
		// Again, unwrap token value if line check is required.
		tk, mv = unwrapValue(mv, &lt)
		switch strings.ToLower(mk) {
		case "name":
			opts.Cluster.Name = mv.(string)
		case "authorization":
			auth, err := parseAuthorization(tk, opts, errors, warnings)
			if err != nil {
				*errors = append(*errors, err)
				continue
			}
			if auth.users != nil {
				err := &configErr{tk, "Cluster authorization does not allow multiple users"}
				*errors = append(*errors, err)
				continue
			}
			opts.Cluster.Username = auth.user
			opts.Cluster.Password = auth.pass
			opts.Cluster.AuthTimeout = auth.timeout

			if auth.defaultPermissions != nil {
				err := &configWarningErr{
					field: mk,
					configErr: configErr{
						token:  tk,
						reason: `setting "permissions" within cluster authorization block is deprecated`,
					},
				}
				*warnings = append(*warnings, err)

				// Do not set permissions if they were specified in top-level cluster block.
				if opts.Cluster.Permissions == nil {
					setClusterPermissions(&opts.Cluster, auth.defaultPermissions)
				}
			}
		case "connect_retries":
			opts.Cluster.ConnectRetries = int(mv.(int64))
		case "permissions":
			perms, err := parseUserPermissions(mv, errors, warnings)
			if err != nil {
				*errors = append(*errors, err)
				continue
			}
			// Dynamic response permissions do not make sense here.
			if perms.Response != nil {
				err := &configErr{tk, "Cluster permissions do not support dynamic responses"}
				*errors = append(*errors, err)
				continue
			}
			// This will possibly override permissions that were define in auth block
			setClusterPermissions(&opts.Cluster, perms)
		default:
			if !tk.IsUsedVariable() {
				err := &unknownConfigFieldErr{
					field: mk,
					configErr: configErr{
						token: tk,
					},
				}
				*errors = append(*errors, err)
				continue
			}
		}
	}
	return nil
}

func parseURL(u string, typ string) (*url.URL, error) {
	urlStr := strings.TrimSpace(u)
	url, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing %s url [%q]", typ, urlStr)
	}
	return url, nil
}

func parseGateway(v interface{}, o *Options, errors *[]error, warnings *[]error) error {
	var lt token
	defer convertPanicToErrorList(&lt, errors)

	tk, v := unwrapValue(v, &lt)
	gm, ok := v.(map[string]interface{})
	if !ok {
		return &configErr{tk, fmt.Sprintf("Expected gateway to be a map, got %T", v)}
	}
	for mk, mv := range gm {
		// Again, unwrap token value if line check is required.
		tk, mv = unwrapValue(mv, &lt)
		switch strings.ToLower(mk) {
		case "name":
			o.Gateway.Name = mv.(string)
		case "authorization":
			auth, err := parseAuthorization(tk, o, errors, warnings)
			if err != nil {
				*errors = append(*errors, err)
				continue
			}
			if auth.users != nil {
				*errors = append(*errors, &configErr{tk, "Gateway authorization does not allow multiple users"})
				continue
			}
			o.Gateway.Username = auth.user
			o.Gateway.Password = auth.pass
			o.Gateway.AuthTimeout = auth.timeout
		case "connect_retries":
			o.Gateway.ConnectRetries = int(mv.(int64))
		case "gateways":
			gateways, err := parseGateways(mv, errors, warnings)
			if err != nil {
				return err
			}
			o.Gateway.Gateways = gateways
		case "reject_unknown":
			o.Gateway.RejectUnknown = mv.(bool)
		default:
			if !tk.IsUsedVariable() {
				err := &unknownConfigFieldErr{
					field: mk,
					configErr: configErr{
						token: tk,
					},
				}
				*errors = append(*errors, err)
				continue
			}
		}
	}
	return nil
}

var dynamicJSAccountLimits = &JetStreamAccountLimits{-1, -1, -1, -1}

// Parses jetstream account limits for an account. Simple setup with boolen is allowed, and we will
// use dynamic account limits.
func parseJetStreamForAccount(v interface{}, acc *Account, errors *[]error, warnings *[]error) error {
	var lt token

	tk, v := unwrapValue(v, &lt)

	// Value here can be bool, or string "enabled" or a map.
	switch vv := v.(type) {
	case bool:
		if vv {
			acc.jsLimits = dynamicJSAccountLimits
		}
	case string:
		switch strings.ToLower(vv) {
		case "enabled", "enable":
			acc.jsLimits = dynamicJSAccountLimits
		case "disabled", "disable":
			acc.jsLimits = nil
		default:
			return &configErr{tk, fmt.Sprintf("Expected 'enabled' or 'disabled' for string value, got '%s'", vv)}
		}
	case map[string]interface{}:
		jsLimits := &JetStreamAccountLimits{-1, -1, -1, -1}
		for mk, mv := range vv {
			tk, mv = unwrapValue(mv, &lt)
			switch strings.ToLower(mk) {
			case "max_memory", "max_mem", "mem", "memory":
				vv, ok := mv.(int64)
				if !ok {
					return &configErr{tk, fmt.Sprintf("Expected a parseable size for %q, got %v", mk, mv)}
				}
				jsLimits.MaxMemory = int64(vv)
			case "max_store", "max_file", "max_disk", "store", "disk":
				vv, ok := mv.(int64)
				if !ok {
					return &configErr{tk, fmt.Sprintf("Expected a parseable size for %q, got %v", mk, mv)}
				}
				jsLimits.MaxStore = int64(vv)
			case "max_streams", "streams":
				vv, ok := mv.(int64)
				if !ok {
					return &configErr{tk, fmt.Sprintf("Expected a parseable size for %q, got %v", mk, mv)}
				}
				jsLimits.MaxStreams = int(vv)
			case "max_consumers", "consumers":
				vv, ok := mv.(int64)
				if !ok {
					return &configErr{tk, fmt.Sprintf("Expected a parseable size for %q, got %v", mk, mv)}
				}
				jsLimits.MaxConsumers = int(vv)
			default:
				if !tk.IsUsedVariable() {
					err := &unknownConfigFieldErr{
						field: mk,
						configErr: configErr{
							token: tk,
						},
					}
					*errors = append(*errors, err)
					continue
				}
			}
		}
		acc.jsLimits = jsLimits
	default:
		return &configErr{tk, fmt.Sprintf("Expected map, bool or string to define JetStream, got %T", v)}
	}
	return nil
}

// Parse enablement of jetstream for a server.
func parseJetStream(v interface{}, opts *Options, errors *[]error, warnings *[]error) error {
	var lt token

	tk, v := unwrapValue(v, &lt)

	// Value here can be bool, or string "enabled" or a map.
	switch vv := v.(type) {
	case bool:
		opts.JetStream = v.(bool)
	case string:
		switch strings.ToLower(vv) {
		case "enabled", "enable":
			opts.JetStream = true
		case "disabled", "disable":
			opts.JetStream = false
		default:
			return &configErr{tk, fmt.Sprintf("Expected 'enabled' or 'disabled' for string value, got '%s'", vv)}
		}
	case map[string]interface{}:
		for mk, mv := range vv {
			tk, mv = unwrapValue(mv, &lt)
			switch strings.ToLower(mk) {
			case "store_dir", "storedir":
				opts.StoreDir = mv.(string)
			case "max_memory_store", "max_mem_store", "max_mem":
				opts.JetStreamMaxMemory = mv.(int64)
			case "max_file_store", "max_file":
				opts.JetStreamMaxStore = mv.(int64)
			default:
				if !tk.IsUsedVariable() {
					err := &unknownConfigFieldErr{
						field: mk,
						configErr: configErr{
							token: tk,
						},
					}
					*errors = append(*errors, err)
					continue
				}
			}
		}
		opts.JetStream = true
	default:
		return &configErr{tk, fmt.Sprintf("Expected map, bool or string to define JetStream, got %T", v)}
	}

	return nil
}

// parseLeafNodes will parse the leaf node config.
func parseLeafNodes(v interface{}, opts *Options, errors *[]error, warnings *[]error) error {
	var lt token
	defer convertPanicToErrorList(&lt, errors)

	tk, v := unwrapValue(v, &lt)
	cm, ok := v.(map[string]interface{})
	if !ok {
		return &configErr{tk, fmt.Sprintf("Expected map to define a leafnode, got %T", v)}
	}

	for mk, mv := range cm {
		// Again, unwrap token value if line check is required.
		tk, mv = unwrapValue(mv, &lt)
		switch strings.ToLower(mk) {
		case "authorization":
			auth, err := parseLeafAuthorization(tk, errors, warnings)
			if err != nil {
				*errors = append(*errors, err)
				continue
			}
			opts.LeafNode.Username = auth.user
			opts.LeafNode.Password = auth.pass
			opts.LeafNode.AuthTimeout = auth.timeout
			opts.LeafNode.Account = auth.acc
			opts.LeafNode.Users = auth.users
			// Validate user info config for leafnode authorization
			if err := validateLeafNodeAuthOptions(opts); err != nil {
				*errors = append(*errors, &configErr{tk, err.Error()})
				continue
			}
		case "remotes":
			// Parse the remote options here.
			remotes, err := parseRemoteLeafNodes(mv, errors, warnings)
			if err != nil {
				continue
			}
			opts.LeafNode.Remotes = remotes
		case "reconnect", "reconnect_delay", "reconnect_interval":
			opts.LeafNode.ReconnectInterval = time.Duration(int(mv.(int64))) * time.Second
		default:
			if !tk.IsUsedVariable() {
				err := &unknownConfigFieldErr{
					field: mk,
					configErr: configErr{
						token: tk,
					},
				}
				*errors = append(*errors, err)
				continue
			}
		}
	}
	return nil
}

// This is the authorization parser adapter for the leafnode's
// authorization config.
func parseLeafAuthorization(v interface{}, errors *[]error, warnings *[]error) (*authorization, error) {
	var (
		am   map[string]interface{}
		tk   token
		lt   token
		auth = &authorization{}
	)
	defer convertPanicToErrorList(&lt, errors)

	_, v = unwrapValue(v, &lt)
	am = v.(map[string]interface{})
	for mk, mv := range am {
		tk, mv = unwrapValue(mv, &lt)
		switch strings.ToLower(mk) {
		case "user", "username":
			auth.user = mv.(string)
		case "pass", "password":
			auth.pass = mv.(string)
		case "timeout":
			at := float64(1)
			switch mv := mv.(type) {
			case int64:
				at = float64(mv)
			case float64:
				at = mv
			}
			auth.timeout = at
		case "users":
			users, err := parseLeafUsers(tk, errors, warnings)
			if err != nil {
				*errors = append(*errors, err)
				continue
			}
			auth.users = users
		case "account":
			auth.acc = mv.(string)
		default:
			if !tk.IsUsedVariable() {
				err := &unknownConfigFieldErr{
					field: mk,
					configErr: configErr{
						token: tk,
					},
				}
				*errors = append(*errors, err)
			}
			continue
		}
	}
	return auth, nil
}

// This is a trimmed down version of parseUsers that is adapted
// for the users possibly defined in the authorization{} section
// of leafnodes {}.
func parseLeafUsers(mv interface{}, errors *[]error, warnings *[]error) ([]*User, error) {
	var (
		tk    token
		lt    token
		users = []*User{}
	)
	defer convertPanicToErrorList(&lt, errors)

	tk, mv = unwrapValue(mv, &lt)
	// Make sure we have an array
	uv, ok := mv.([]interface{})
	if !ok {
		return nil, &configErr{tk, fmt.Sprintf("Expected users field to be an array, got %v", mv)}
	}
	for _, u := range uv {
		tk, u = unwrapValue(u, &lt)
		// Check its a map/struct
		um, ok := u.(map[string]interface{})
		if !ok {
			err := &configErr{tk, fmt.Sprintf("Expected user entry to be a map/struct, got %v", u)}
			*errors = append(*errors, err)
			continue
		}
		user := &User{}
		for k, v := range um {
			tk, v = unwrapValue(v, &lt)
			switch strings.ToLower(k) {
			case "user", "username":
				user.Username = v.(string)
			case "pass", "password":
				user.Password = v.(string)
			case "account":
				// We really want to save just the account name here, but
				// the User object is *Account. So we create an account object
				// but it won't be registered anywhere. The server will just
				// use opts.LeafNode.Users[].Account.Name. Alternatively
				// we need to create internal objects to store u/p and account
				// name and have a server structure to hold that.
				user.Account = NewAccount(v.(string))
			default:
				if !tk.IsUsedVariable() {
					err := &unknownConfigFieldErr{
						field: k,
						configErr: configErr{
							token: tk,
						},
					}
					*errors = append(*errors, err)
					continue
				}
			}
		}
		users = append(users, user)
	}
	return users, nil
}

func parseRemoteLeafNodes(v interface{}, errors *[]error, warnings *[]error) ([]*RemoteLeafOpts, error) {
	var lt token
	defer convertPanicToErrorList(&lt, errors)

	tk, v := unwrapValue(v, &lt)
	ra, ok := v.([]interface{})
	if !ok {
		return nil, &configErr{tk, fmt.Sprintf("Expected remotes field to be an array, got %T", v)}
	}
	remotes := make([]*RemoteLeafOpts, 0, len(ra))
	for _, r := range ra {
		tk, r = unwrapValue(r, &lt)
		// Check its a map/struct
		rm, ok := r.(map[string]interface{})
		if !ok {
			*errors = append(*errors, &configErr{tk, fmt.Sprintf("Expected remote leafnode entry to be a map/struct, got %v", r)})
			continue
		}
		remote := &RemoteLeafOpts{}
		for k, v := range rm {
			tk, v = unwrapValue(v, &lt)
			switch strings.ToLower(k) {
			case "account", "local":
				remote.LocalAccount = v.(string)
			case "creds", "credentials":
				p, err := expandPath(v.(string))
				if err != nil {
					*errors = append(*errors, &configErr{tk, err.Error()})
					continue
				}
				remote.Credentials = p
			case "hub":
				remote.Hub = v.(bool)
			case "deny_imports", "deny_import":
				subjects, err := parseSubjects(tk, errors, warnings)
				if err != nil {
					*errors = append(*errors, err)
					continue
				}
				remote.DenyImports = subjects
			case "deny_exports", "deny_export":
				subjects, err := parseSubjects(tk, errors, warnings)
				if err != nil {
					*errors = append(*errors, err)
					continue
				}
				remote.DenyExports = subjects
			default:
				if !tk.IsUsedVariable() {
					err := &unknownConfigFieldErr{
						field: k,
						configErr: configErr{
							token: tk,
						},
					}
					*errors = append(*errors, err)
					continue
				}
			}
		}
		remotes = append(remotes, remote)
	}
	return remotes, nil
}

func parseGateways(v interface{}, errors *[]error, warnings *[]error) ([]*RemoteGatewayOpts, error) {
	var lt token
	defer convertPanicToErrorList(&lt, errors)

	tk, v := unwrapValue(v, &lt)
	// Make sure we have an array
	ga, ok := v.([]interface{})
	if !ok {
		return nil, &configErr{tk, fmt.Sprintf("Expected gateways field to be an array, got %T", v)}
	}
	gateways := []*RemoteGatewayOpts{}
	for _, g := range ga {
		tk, g = unwrapValue(g, &lt)
		// Check its a map/struct
		gm, ok := g.(map[string]interface{})
		if !ok {
			*errors = append(*errors, &configErr{tk, fmt.Sprintf("Expected gateway entry to be a map/struct, got %v", g)})
			continue
		}
		gateway := &RemoteGatewayOpts{}
		for k, v := range gm {
			tk, v = unwrapValue(v, &lt)
			switch strings.ToLower(k) {
			case "name":
				gateway.Name = v.(string)
			default:
				if !tk.IsUsedVariable() {
					err := &unknownConfigFieldErr{
						field: k,
						configErr: configErr{
							token: tk,
						},
					}
					*errors = append(*errors, err)
					continue
				}
			}
		}
		gateways = append(gateways, gateway)
	}
	return gateways, nil
}

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

// parseAccounts will parse the different accounts syntax.
func parseAccounts(v interface{}, opts *Options, errors *[]error, warnings *[]error) error {
	var (
		importStreams  []*importStream
		importServices []*importService
		exportStreams  []*export
		exportServices []*export
		lt             token
	)
	defer convertPanicToErrorList(&lt, errors)

	tk, v := unwrapValue(v, &lt)
	switch vv := v.(type) {
	// Simple array of account names.
	case []interface{}, []string:
		m := make(map[string]struct{}, len(v.([]interface{})))
		for _, n := range v.([]interface{}) {
			tk, name := unwrapValue(n, &lt)
			ns := name.(string)
			// Check for reserved names.
			if isReservedAccount(ns) {
				err := &configErr{tk, fmt.Sprintf("%q is a Reserved Account", ns)}
				*errors = append(*errors, err)
				continue
			}
			if _, ok := m[ns]; ok {
				err := &configErr{tk, fmt.Sprintf("Duplicate Account Entry: %s", ns)}
				*errors = append(*errors, err)
				continue
			}
			opts.Accounts = append(opts.Accounts, NewAccount(ns))
			m[ns] = struct{}{}
		}
	// More common map entry
	case map[string]interface{}:
		// Track users across accounts, must be unique across
		// accounts and nkeys vs users.
		uorn := make(map[string]struct{})
		for aname, mv := range vv {
			tk, amv := unwrapValue(mv, &lt)

			// Skip referenced config vars within the account block.
			if tk.IsUsedVariable() {
				continue
			}

			// These should be maps.
			mv, ok := amv.(map[string]interface{})
			if !ok {
				err := &configErr{tk, "Expected map entries for accounts"}
				*errors = append(*errors, err)
				continue
			}
			if isReservedAccount(aname) {
				err := &configErr{tk, fmt.Sprintf("%q is a Reserved Account", aname)}
				*errors = append(*errors, err)
				continue
			}
			var (
				users   []*User
				nkeyUsr []*NkeyUser
				usersTk token
			)
			acc := NewAccount(aname)
			opts.Accounts = append(opts.Accounts, acc)

			for k, v := range mv {
				tk, mv := unwrapValue(v, &lt)
				switch strings.ToLower(k) {
				case "nkey":
					nk, ok := mv.(string)
					if !ok { // || !nkeys.IsValidPublicAccountKey(nk) {
						err := &configErr{tk, fmt.Sprintf("Not a valid public nkey for an account: %q", mv)}
						*errors = append(*errors, err)
						continue
					}
					acc.Nkey = nk
				case "imports":
					streams, services, err := parseAccountImports(tk, acc, errors, warnings)
					if err != nil {
						*errors = append(*errors, err)
						continue
					}
					importStreams = append(importStreams, streams...)
					importServices = append(importServices, services...)
				case "exports":
					streams, services, err := parseAccountExports(tk, acc, errors, warnings)
					if err != nil {
						*errors = append(*errors, err)
						continue
					}
					exportStreams = append(exportStreams, streams...)
					exportServices = append(exportServices, services...)
				case "jetstream":
					err := parseJetStreamForAccount(mv, acc, errors, warnings)
					if err != nil {
						*errors = append(*errors, err)
						continue
					}
				case "users":
					var err error
					usersTk = tk
					nkeyUsr, users, err = parseUsers(mv, opts, errors, warnings)
					if err != nil {
						*errors = append(*errors, err)
						continue
					}
				case "default_permissions":
					permissions, err := parseUserPermissions(tk, errors, warnings)
					if err != nil {
						*errors = append(*errors, err)
						continue
					}
					acc.defaultPerms = permissions
				default:
					if !tk.IsUsedVariable() {
						err := &unknownConfigFieldErr{
							field: k,
							configErr: configErr{
								token: tk,
							},
						}
						*errors = append(*errors, err)
					}
				}
			}
			applyDefaultPermissions(users, nkeyUsr, acc.defaultPerms)
			for _, u := range nkeyUsr {
				if _, ok := uorn[u.Nkey]; ok {
					err := &configErr{usersTk, fmt.Sprintf("Duplicate nkey %q detected", u.Nkey)}
					*errors = append(*errors, err)
					continue
				}
				uorn[u.Nkey] = struct{}{}
				u.Account = acc
			}
			opts.Nkeys = append(opts.Nkeys, nkeyUsr...)
			for _, u := range users {
				if _, ok := uorn[u.Username]; ok {
					err := &configErr{usersTk, fmt.Sprintf("Duplicate user %q detected", u.Username)}
					*errors = append(*errors, err)
					continue
				}
				uorn[u.Username] = struct{}{}
				u.Account = acc
			}
			opts.Users = append(opts.Users, users...)
		}
	}
	lt = tk
	// Bail already if there are previous errors.
	if len(*errors) > 0 {
		return nil
	}

	// Parse Imports and Exports here after all accounts defined.
	// Do exports first since they need to be defined for imports to succeed
	// since we do permissions checks.

	// Create a lookup map for accounts lookups.
	am := make(map[string]*Account, len(opts.Accounts))
	for _, a := range opts.Accounts {
		am[a.Name] = a
	}
	// Do stream exports
	for _, stream := range exportStreams {
		// Make array of accounts if applicable.
		var accounts []*Account
		for _, an := range stream.accs {
			ta := am[an]
			if ta == nil {
				msg := fmt.Sprintf("%q account not defined for stream export", an)
				*errors = append(*errors, &configErr{tk, msg})
				continue
			}
			accounts = append(accounts, ta)
		}
		if err := stream.acc.AddStreamExport(stream.sub, accounts); err != nil {
			msg := fmt.Sprintf("Error adding stream export %q: %v", stream.sub, err)
			*errors = append(*errors, &configErr{tk, msg})
			continue
		}
	}
	for _, service := range exportServices {
		// Make array of accounts if applicable.
		var accounts []*Account
		for _, an := range service.accs {
			ta := am[an]
			if ta == nil {
				msg := fmt.Sprintf("%q account not defined for service export", an)
				*errors = append(*errors, &configErr{tk, msg})
				continue
			}
			accounts = append(accounts, ta)
		}
		if err := service.acc.AddServiceExportWithResponse(service.sub, service.rt, accounts); err != nil {
			msg := fmt.Sprintf("Error adding service export %q: %v", service.sub, err)
			*errors = append(*errors, &configErr{tk, msg})
			continue
		}

		if service.rthr != 0 {
			// Response threshold was set in options.
			if err := service.acc.SetServiceExportResponseThreshold(service.sub, service.rthr); err != nil {
				msg := fmt.Sprintf("Error adding service export response threshold for %q: %v", service.sub, err)
				*errors = append(*errors, &configErr{tk, msg})
				continue
			}
		}

		if service.lat != nil {
			if opts.SystemAccount == "" {
				msg := fmt.Sprintf("Error adding service latency sampling for %q: %v", service.sub, ErrNoSysAccount.Error())
				*errors = append(*errors, &configErr{tk, msg})
				continue
			}

			if err := service.acc.TrackServiceExportWithSampling(service.sub, service.lat.subject, int(service.lat.sampling)); err != nil {
				msg := fmt.Sprintf("Error adding service latency sampling for %q on subject %q: %v", service.sub, service.lat.subject, err)
				*errors = append(*errors, &configErr{tk, msg})
				continue
			}
		}
	}
	for _, stream := range importStreams {
		ta := am[stream.an]
		if ta == nil {
			msg := fmt.Sprintf("%q account not defined for stream import", stream.an)
			*errors = append(*errors, &configErr{tk, msg})
			continue
		}
		if err := stream.acc.AddStreamImport(ta, stream.sub, stream.pre); err != nil {
			msg := fmt.Sprintf("Error adding stream import %q: %v", stream.sub, err)
			*errors = append(*errors, &configErr{tk, msg})
			continue
		}
	}
	for _, service := range importServices {
		ta := am[service.an]
		if ta == nil {
			msg := fmt.Sprintf("%q account not defined for service import", service.an)
			*errors = append(*errors, &configErr{tk, msg})
			continue
		}
		if service.to == "" {
			service.to = service.sub
		}
		if err := service.acc.AddServiceImport(ta, service.to, service.sub); err != nil {
			msg := fmt.Sprintf("Error adding service import %q: %v", service.sub, err)
			*errors = append(*errors, &configErr{tk, msg})
			continue
		}
		if err := service.acc.SetServiceImportSharing(ta, service.sub, service.share); err != nil {
			msg := fmt.Sprintf("Error setting service import sharing %q: %v", service.sub, err)
			*errors = append(*errors, &configErr{tk, msg})
			continue
		}
	}

	return nil
}

// Parse the account exports
func parseAccountExports(v interface{}, acc *Account, errors, warnings *[]error) ([]*export, []*export, error) {
	var lt token
	defer convertPanicToErrorList(&lt, errors)

	// This should be an array of objects/maps.
	tk, v := unwrapValue(v, &lt)
	ims, ok := v.([]interface{})
	if !ok {
		return nil, nil, &configErr{tk, fmt.Sprintf("Exports should be an array, got %T", v)}
	}

	var services []*export
	var streams []*export

	for _, v := range ims {
		// Should have stream or service
		stream, service, err := parseExportStreamOrService(v, errors, warnings)
		if err != nil {
			*errors = append(*errors, err)
			continue
		}
		if service != nil {
			service.acc = acc
			services = append(services, service)
		}
		if stream != nil {
			stream.acc = acc
			streams = append(streams, stream)
		}
	}
	return streams, services, nil
}

// Parse the account imports
func parseAccountImports(v interface{}, acc *Account, errors, warnings *[]error) ([]*importStream, []*importService, error) {
	var lt token
	defer convertPanicToErrorList(&lt, errors)

	// This should be an array of objects/maps.
	tk, v := unwrapValue(v, &lt)
	ims, ok := v.([]interface{})
	if !ok {
		return nil, nil, &configErr{tk, fmt.Sprintf("Imports should be an array, got %T", v)}
	}

	var services []*importService
	var streams []*importStream
	svcSubjects := map[string]*importService{}

	for _, v := range ims {
		// Should have stream or service
		stream, service, err := parseImportStreamOrService(v, errors, warnings)
		if err != nil {
			*errors = append(*errors, err)
			continue
		}
		if service != nil {
			if dup := svcSubjects[service.to]; dup != nil {
				tk, _ := unwrapValue(v, &lt)
				err := &configErr{tk,
					fmt.Sprintf("Duplicate service import subject %q, previously used in import for account %q, subject %q",
						service.to, dup.an, dup.sub)}
				*errors = append(*errors, err)
				continue
			}
			svcSubjects[service.to] = service
			service.acc = acc
			services = append(services, service)
		}
		if stream != nil {
			stream.acc = acc
			streams = append(streams, stream)
		}
	}
	return streams, services, nil
}

// Helper to parse an embedded account description for imported services or streams.
func parseAccount(v map[string]interface{}, errors, warnings *[]error) (string, string, error) {
	var lt token
	defer convertPanicToErrorList(&lt, errors)

	var accountName, subject string
	for mk, mv := range v {
		tk, mv := unwrapValue(mv, &lt)
		switch strings.ToLower(mk) {
		case "account":
			accountName = mv.(string)
		case "subject":
			subject = mv.(string)
		default:
			if !tk.IsUsedVariable() {
				err := &unknownConfigFieldErr{
					field: mk,
					configErr: configErr{
						token: tk,
					},
				}
				*errors = append(*errors, err)
			}
		}
	}
	return accountName, subject, nil
}

// Parse an export stream or service.
// e.g.
//   {stream: "public.>"} # No accounts means public.
//   {stream: "synadia.private.>", accounts: [cncf, natsio]}
//   {service: "pub.request"} # No accounts means public.
//   {service: "pub.special.request", accounts: [nats.io]}
func parseExportStreamOrService(v interface{}, errors, warnings *[]error) (*export, *export, error) {
	var (
		curStream  *export
		curService *export
		accounts   []string
		rt         ServiceRespType
		rtSeen     bool
		rtToken    token
		lat        *serviceLatency
		threshSeen bool
		thresh     time.Duration
		latToken   token
		lt         token
	)
	defer convertPanicToErrorList(&lt, errors)

	tk, v := unwrapValue(v, &lt)
	vv, ok := v.(map[string]interface{})
	if !ok {
		return nil, nil, &configErr{tk, fmt.Sprintf("Export Items should be a map with type entry, got %T", v)}
	}
	for mk, mv := range vv {
		tk, mv := unwrapValue(mv, &lt)
		switch strings.ToLower(mk) {
		case "stream":
			if curService != nil {
				err := &configErr{tk, fmt.Sprintf("Detected stream %q but already saw a service", mv)}
				*errors = append(*errors, err)
				continue
			}
			if rtToken != nil {
				err := &configErr{rtToken, "Detected response directive on non-service"}
				*errors = append(*errors, err)
				continue
			}
			if latToken != nil {
				err := &configErr{latToken, "Detected latency directive on non-service"}
				*errors = append(*errors, err)
				continue
			}
			mvs, ok := mv.(string)
			if !ok {
				err := &configErr{tk, fmt.Sprintf("Expected stream name to be string, got %T", mv)}
				*errors = append(*errors, err)
				continue
			}
			curStream = &export{sub: mvs}
			if accounts != nil {
				curStream.accs = accounts
			}
		case "service":
			if curStream != nil {
				err := &configErr{tk, fmt.Sprintf("Detected service %q but already saw a stream", mv)}
				*errors = append(*errors, err)
				continue
			}
			mvs, ok := mv.(string)
			if !ok {
				err := &configErr{tk, fmt.Sprintf("Expected service name to be string, got %T", mv)}
				*errors = append(*errors, err)
				continue
			}
			curService = &export{sub: mvs}
			if accounts != nil {
				curService.accs = accounts
			}
			if rtSeen {
				curService.rt = rt
			}
			if lat != nil {
				curService.lat = lat
			}
			if threshSeen {
				curService.rthr = thresh
			}
		case "response", "response_type":
			if rtSeen {
				err := &configErr{tk, "Duplicate response type definition"}
				*errors = append(*errors, err)
				continue
			}
			rtSeen = true
			rtToken = tk
			mvs, ok := mv.(string)
			if !ok {
				err := &configErr{tk, fmt.Sprintf("Expected response type to be string, got %T", mv)}
				*errors = append(*errors, err)
				continue
			}
			switch strings.ToLower(mvs) {
			case "single", "singleton":
				rt = Singleton
			case "stream":
				rt = Streamed
			case "chunk", "chunked":
				rt = Chunked
			default:
				err := &configErr{tk, fmt.Sprintf("Unknown response type: %q", mvs)}
				*errors = append(*errors, err)
				continue
			}
			if curService != nil {
				curService.rt = rt
			}
			if curStream != nil {
				err := &configErr{tk, "Detected response directive on non-service"}
				*errors = append(*errors, err)
			}
		case "threshold", "response_threshold", "response_max_time", "response_time":
			if threshSeen {
				err := &configErr{tk, "Duplicate response threshold detected"}
				*errors = append(*errors, err)
				continue
			}
			threshSeen = true
			mvs, ok := mv.(string)
			if !ok {
				err := &configErr{tk, fmt.Sprintf("Expected response threshold to be a parseable time duration, got %T", mv)}
				*errors = append(*errors, err)
				continue
			}
			var err error
			thresh, err = time.ParseDuration(mvs)
			if err != nil {
				err := &configErr{tk, fmt.Sprintf("Expected response threshold to be a parseable time duration, got %q", mvs)}
				*errors = append(*errors, err)
				continue
			}
			if curService != nil {
				curService.rthr = thresh
			}
			if curStream != nil {
				err := &configErr{tk, "Detected response directive on non-service"}
				*errors = append(*errors, err)
			}
		case "accounts":
			for _, iv := range mv.([]interface{}) {
				_, mv := unwrapValue(iv, &lt)
				accounts = append(accounts, mv.(string))
			}
			if curStream != nil {
				curStream.accs = accounts
			} else if curService != nil {
				curService.accs = accounts
			}
		case "latency":
			latToken = tk
			var err error
			lat, err = parseServiceLatency(tk, mv)
			if err != nil {
				*errors = append(*errors, err)
				continue
			}
			if curStream != nil {
				err = &configErr{tk, "Detected latency directive on non-service"}
				*errors = append(*errors, err)
				continue
			}
			if curService != nil {
				curService.lat = lat
			}
		default:
			if !tk.IsUsedVariable() {
				err := &unknownConfigFieldErr{
					field: mk,
					configErr: configErr{
						token: tk,
					},
				}
				*errors = append(*errors, err)
			}
		}
	}
	return curStream, curService, nil
}

// parseServiceLatency returns a latency config block.
func parseServiceLatency(root token, v interface{}) (l *serviceLatency, retErr error) {
	var lt token
	defer convertPanicToError(&lt, &retErr)

	if subject, ok := v.(string); ok {
		return &serviceLatency{
			subject:  subject,
			sampling: DEFAULT_SERVICE_LATENCY_SAMPLING,
		}, nil
	}

	latency, ok := v.(map[string]interface{})
	if !ok {
		return nil, &configErr{token: root,
			reason: fmt.Sprintf("Expected latency entry to be a map/struct or string, got %T", v)}
	}

	sl := serviceLatency{
		sampling: DEFAULT_SERVICE_LATENCY_SAMPLING,
	}

	// Read sampling value.
	if v, ok := latency["sampling"]; ok {
		tk, v := unwrapValue(v, &lt)
		header := false
		var sample int64
		switch vv := v.(type) {
		case int64:
			// Sample is an int, like 50.
			sample = vv
		case string:
			// Sample is a string, like "50%".
			if strings.ToLower(strings.TrimSpace(vv)) == "headers" {
				header = true
				sample = 0
				break
			}
			s := strings.TrimSuffix(vv, "%")
			n, err := strconv.Atoi(s)
			if err != nil {
				return nil, &configErr{token: tk,
					reason: fmt.Sprintf("Failed to parse latency sample: %v", err)}
			}
			sample = int64(n)
		default:
			return nil, &configErr{token: tk,
				reason: fmt.Sprintf("Expected latency sample to be a string or map/struct, got %T", v)}
		}
		if !header {
			if sample < 1 || sample > 100 {
				return nil, &configErr{token: tk,
					reason: ErrBadSampling.Error()}
			}
		}

		sl.sampling = int8(sample)
	}

	// Read subject value.
	v, ok = latency["subject"]
	if !ok {
		return nil, &configErr{token: root,
			reason: "Latency subject required, but missing"}
	}

	tk, v := unwrapValue(v, &lt)
	subject, ok := v.(string)
	if !ok {
		return nil, &configErr{token: tk,
			reason: fmt.Sprintf("Expected latency subject to be a string, got %T", subject)}
	}
	sl.subject = subject

	return &sl, nil
}

// Parse an import stream or service.
// e.g.
//   {stream: {account: "synadia", subject:"public.synadia"}, prefix: "imports.synadia"}
//   {stream: {account: "synadia", subject:"synadia.private.*"}}
//   {service: {account: "synadia", subject: "pub.special.request"}, to: "synadia.request"}
func parseImportStreamOrService(v interface{}, errors, warnings *[]error) (*importStream, *importService, error) {
	var (
		curStream  *importStream
		curService *importService
		pre, to    string
		share      bool
		lt         token
	)
	defer convertPanicToErrorList(&lt, errors)

	tk, mv := unwrapValue(v, &lt)
	vv, ok := mv.(map[string]interface{})
	if !ok {
		return nil, nil, &configErr{tk, fmt.Sprintf("Import Items should be a map with type entry, got %T", mv)}
	}
	for mk, mv := range vv {
		tk, mv := unwrapValue(mv, &lt)
		switch strings.ToLower(mk) {
		case "stream":
			if curService != nil {
				err := &configErr{tk, "Detected stream but already saw a service"}
				*errors = append(*errors, err)
				continue
			}
			ac, ok := mv.(map[string]interface{})
			if !ok {
				err := &configErr{tk, fmt.Sprintf("Stream entry should be an account map, got %T", mv)}
				*errors = append(*errors, err)
				continue
			}
			// Make sure this is a map with account and subject
			accountName, subject, err := parseAccount(ac, errors, warnings)
			if err != nil {
				*errors = append(*errors, err)
				continue
			}
			if accountName == "" || subject == "" {
				err := &configErr{tk, "Expect an account name and a subject"}
				*errors = append(*errors, err)
				continue
			}
			curStream = &importStream{an: accountName, sub: subject}
			if pre != "" {
				curStream.pre = pre
			}
		case "service":
			if curStream != nil {
				err := &configErr{tk, "Detected service but already saw a stream"}
				*errors = append(*errors, err)
				continue
			}
			ac, ok := mv.(map[string]interface{})
			if !ok {
				err := &configErr{tk, fmt.Sprintf("Service entry should be an account map, got %T", mv)}
				*errors = append(*errors, err)
				continue
			}
			// Make sure this is a map with account and subject
			accountName, subject, err := parseAccount(ac, errors, warnings)
			if err != nil {
				*errors = append(*errors, err)
				continue
			}
			if accountName == "" || subject == "" {
				err := &configErr{tk, "Expect an account name and a subject"}
				*errors = append(*errors, err)
				continue
			}
			curService = &importService{an: accountName, sub: subject}
			if to != "" {
				curService.to = to
			} else {
				curService.to = subject
			}
			curService.share = share
		case "prefix":
			pre = mv.(string)
			if curStream != nil {
				curStream.pre = pre
			}
		case "to":
			to = mv.(string)
			if curService != nil {
				curService.to = to
			}
		case "share":
			share = mv.(bool)
			if curService != nil {
				curService.share = share
			}
		default:
			if !tk.IsUsedVariable() {
				err := &unknownConfigFieldErr{
					field: mk,
					configErr: configErr{
						token: tk,
					},
				}
				*errors = append(*errors, err)
			}
		}

	}
	return curStream, curService, nil
}

// Apply permission defaults to users/nkeyuser that don't have their own.
func applyDefaultPermissions(users []*User, nkeys []*NkeyUser, defaultP *Permissions) {
	if defaultP == nil {
		return
	}
	for _, user := range users {
		if user.Permissions == nil {
			user.Permissions = defaultP
		}
	}
	for _, user := range nkeys {
		if user.Permissions == nil {
			user.Permissions = defaultP
		}
	}
}

// Helper function to parse Authorization configs.
func parseAuthorization(v interface{}, opts *Options, errors *[]error, warnings *[]error) (*authorization, error) {
	var (
		am   map[string]interface{}
		tk   token
		lt   token
		auth = &authorization{}
	)
	defer convertPanicToErrorList(&lt, errors)

	_, v = unwrapValue(v, &lt)
	am = v.(map[string]interface{})
	for mk, mv := range am {
		tk, mv = unwrapValue(mv, &lt)
		switch strings.ToLower(mk) {
		case "user", "username":
			auth.user = mv.(string)
		case "pass", "password":
			auth.pass = mv.(string)
		case "token":
			auth.token = mv.(string)
		case "timeout":
			at := float64(1)
			switch mv := mv.(type) {
			case int64:
				at = float64(mv)
			case float64:
				at = mv
			}
			auth.timeout = at
		case "users":
			nkeys, users, err := parseUsers(tk, opts, errors, warnings)
			if err != nil {
				*errors = append(*errors, err)
				continue
			}
			auth.users = users
			auth.nkeys = nkeys
		case "default_permission", "default_permissions", "permissions":
			permissions, err := parseUserPermissions(tk, errors, warnings)
			if err != nil {
				*errors = append(*errors, err)
				continue
			}
			auth.defaultPermissions = permissions
		default:
			if !tk.IsUsedVariable() {
				err := &unknownConfigFieldErr{
					field: mk,
					configErr: configErr{
						token: tk,
					},
				}
				*errors = append(*errors, err)
			}
			continue
		}

		applyDefaultPermissions(auth.users, auth.nkeys, auth.defaultPermissions)
	}
	return auth, nil
}

// Helper function to parse multiple users array with optional permissions.
func parseUsers(mv interface{}, opts *Options, errors *[]error, warnings *[]error) ([]*NkeyUser, []*User, error) {
	var (
		tk    token
		lt    token
		keys  []*NkeyUser
		users = []*User{}
	)
	defer convertPanicToErrorList(&lt, errors)
	tk, mv = unwrapValue(mv, &lt)

	// Make sure we have an array
	uv, ok := mv.([]interface{})
	if !ok {
		return nil, nil, &configErr{tk, fmt.Sprintf("Expected users field to be an array, got %v", mv)}
	}
	for _, u := range uv {
		tk, u = unwrapValue(u, &lt)

		// Check its a map/struct
		um, ok := u.(map[string]interface{})
		if !ok {
			err := &configErr{tk, fmt.Sprintf("Expected user entry to be a map/struct, got %v", u)}
			*errors = append(*errors, err)
			continue
		}

		var (
			user  = &User{}
			nkey  = &NkeyUser{}
			perms *Permissions
			err   error
		)
		for k, v := range um {
			// Also needs to unwrap first
			tk, v = unwrapValue(v, &lt)

			switch strings.ToLower(k) {
			case "nkey":
				nkey.Nkey = v.(string)
			case "user", "username":
				user.Username = v.(string)
			case "pass", "password":
				user.Password = v.(string)
			case "permission", "permissions", "authorization":
				perms, err = parseUserPermissions(tk, errors, warnings)
				if err != nil {
					*errors = append(*errors, err)
					continue
				}
			default:
				if !tk.IsUsedVariable() {
					err := &unknownConfigFieldErr{
						field: k,
						configErr: configErr{
							token: tk,
						},
					}
					*errors = append(*errors, err)
					continue
				}
			}
		}
		// Place perms if we have them.
		if perms != nil {
			// nkey takes precedent.
			if nkey.Nkey != "" {
				nkey.Permissions = perms
			} else {
				user.Permissions = perms
			}
		}

		// Check to make sure we have at least an nkey or username <password> defined.
		if nkey.Nkey == "" && user.Username == "" {
			return nil, nil, &configErr{tk, "User entry requires a user"}
		} else if nkey.Nkey != "" {
			// Make sure the nkey a proper public nkey for a user..
			/*
				if !nkeys.IsValidPublicUserKey(nkey.Nkey) {
					return nil, nil, &configErr{tk, "Not a valid public nkey for a user"}
				}
			*/
			// If we have user or password defined here that is an error.
			if user.Username != "" || user.Password != "" {
				return nil, nil, &configErr{tk, "Nkey users do not take usernames or passwords"}
			}
			keys = append(keys, nkey)
		} else {
			users = append(users, user)
		}
	}
	return keys, users, nil
}

// Helper function to parse user/account permissions
func parseUserPermissions(mv interface{}, errors, warnings *[]error) (*Permissions, error) {
	var (
		tk token
		lt token
		p  = &Permissions{}
	)
	defer convertPanicToErrorList(&lt, errors)

	tk, mv = unwrapValue(mv, &lt)
	pm, ok := mv.(map[string]interface{})
	if !ok {
		return nil, &configErr{tk, fmt.Sprintf("Expected permissions to be a map/struct, got %+v", mv)}
	}
	for k, v := range pm {
		tk, mv = unwrapValue(v, &lt)

		switch strings.ToLower(k) {
		// For routes:
		// Import is Publish
		// Export is Subscribe
		case "pub", "publish", "import":
			perms, err := parseVariablePermissions(mv, errors, warnings)
			if err != nil {
				*errors = append(*errors, err)
				continue
			}
			p.Publish = perms
		case "sub", "subscribe", "export":
			perms, err := parseVariablePermissions(mv, errors, warnings)
			if err != nil {
				*errors = append(*errors, err)
				continue
			}
			p.Subscribe = perms
		case "publish_allow_responses", "allow_responses":
			rp := &ResponsePermission{
				MaxMsgs: DEFAULT_ALLOW_RESPONSE_MAX_MSGS,
				Expires: DEFAULT_ALLOW_RESPONSE_EXPIRATION,
			}
			// Try boolean first
			responses, ok := mv.(bool)
			if ok {
				if responses {
					p.Response = rp
				}
			} else {
				p.Response = parseAllowResponses(v, errors, warnings)
			}
			if p.Response != nil {
				if p.Publish == nil {
					p.Publish = &SubjectPermission{}
				}
				if p.Publish.Allow == nil {
					// We turn off the blanket allow statement.
					p.Publish.Allow = []string{}
				}
			}
		default:
			if !tk.IsUsedVariable() {
				err := &configErr{tk, fmt.Sprintf("Unknown field %q parsing permissions", k)}
				*errors = append(*errors, err)
			}
		}
	}
	return p, nil
}

// Top level parser for authorization configurations.
func parseVariablePermissions(v interface{}, errors, warnings *[]error) (*SubjectPermission, error) {
	switch vv := v.(type) {
	case map[string]interface{}:
		// New style with allow and/or deny properties.
		return parseSubjectPermission(vv, errors, warnings)
	default:
		// Old style
		return parseOldPermissionStyle(v, errors, warnings)
	}
}

// Helper function to parse subject singletons and/or arrays
func parseSubjects(v interface{}, errors, warnings *[]error) ([]string, error) {
	var lt token
	defer convertPanicToErrorList(&lt, errors)

	tk, v := unwrapValue(v, &lt)

	var subjects []string
	switch vv := v.(type) {
	case string:
		subjects = append(subjects, vv)
	case []string:
		subjects = vv
	case []interface{}:
		for _, i := range vv {
			tk, i := unwrapValue(i, &lt)

			subject, ok := i.(string)
			if !ok {
				return nil, &configErr{tk, "Subject in permissions array cannot be cast to string"}
			}
			subjects = append(subjects, subject)
		}
	default:
		return nil, &configErr{tk, fmt.Sprintf("Expected subject permissions to be a subject, or array of subjects, got %T", v)}
	}
	if err := checkSubjectArray(subjects); err != nil {
		return nil, &configErr{tk, err.Error()}
	}
	return subjects, nil
}

// Helper function to parse a ResponsePermission.
func parseAllowResponses(v interface{}, errors, warnings *[]error) *ResponsePermission {
	var lt token
	defer convertPanicToErrorList(&lt, errors)

	tk, v := unwrapValue(v, &lt)
	// Check if this is a map.
	pm, ok := v.(map[string]interface{})
	if !ok {
		err := &configErr{tk, "error parsing response permissions, expected a boolean or a map"}
		*errors = append(*errors, err)
		return nil
	}

	rp := &ResponsePermission{
		MaxMsgs: DEFAULT_ALLOW_RESPONSE_MAX_MSGS,
		Expires: DEFAULT_ALLOW_RESPONSE_EXPIRATION,
	}

	for k, v := range pm {
		tk, v = unwrapValue(v, &lt)
		switch strings.ToLower(k) {
		case "max", "max_msgs", "max_messages", "max_responses":
			max := int(v.(int64))
			// Negative values are accepted (mean infinite), and 0
			// means default value (set above).
			if max != 0 {
				rp.MaxMsgs = max
			}
		case "expires", "expiration", "ttl":
			wd, ok := v.(string)
			if ok {
				ttl, err := time.ParseDuration(wd)
				if err != nil {
					err := &configErr{tk, fmt.Sprintf("error parsing expires: %v", err)}
					*errors = append(*errors, err)
					return nil
				}
				// Negative values are accepted (mean infinite), and 0
				// means default value (set above).
				if ttl != 0 {
					rp.Expires = ttl
				}
			} else {
				err := &configErr{tk, "error parsing expires, not a duration string"}
				*errors = append(*errors, err)
				return nil
			}
		default:
			if !tk.IsUsedVariable() {
				err := &configErr{tk, fmt.Sprintf("Unknown field %q parsing permissions", k)}
				*errors = append(*errors, err)
			}
		}
	}
	return rp
}

// Helper function to parse old style authorization configs.
func parseOldPermissionStyle(v interface{}, errors, warnings *[]error) (*SubjectPermission, error) {
	subjects, err := parseSubjects(v, errors, warnings)
	if err != nil {
		return nil, err
	}
	return &SubjectPermission{Allow: subjects}, nil
}

// Helper function to parse new style authorization into a SubjectPermission with Allow and Deny.
func parseSubjectPermission(v interface{}, errors, warnings *[]error) (*SubjectPermission, error) {
	var lt token
	defer convertPanicToErrorList(&lt, errors)

	m := v.(map[string]interface{})
	if len(m) == 0 {
		return nil, nil
	}
	p := &SubjectPermission{}
	for k, v := range m {
		tk, _ := unwrapValue(v, &lt)
		switch strings.ToLower(k) {
		case "allow":
			subjects, err := parseSubjects(tk, errors, warnings)
			if err != nil {
				*errors = append(*errors, err)
				continue
			}
			p.Allow = subjects
		case "deny":
			subjects, err := parseSubjects(tk, errors, warnings)
			if err != nil {
				*errors = append(*errors, err)
				continue
			}
			p.Deny = subjects
		default:
			if !tk.IsUsedVariable() {
				err := &configErr{tk, fmt.Sprintf("Unknown field name %q parsing subject permissions, only 'allow' or 'deny' are permitted", k)}
				*errors = append(*errors, err)
			}
		}
	}
	return p, nil
}

// Helper function to validate subjects, etc for account permissioning.
func checkSubjectArray(sa []string) error {
	for _, s := range sa {
		if !IsValidSubject(s) {
			return fmt.Errorf("subject %q is not a valid subject", s)
		}
	}
	return nil
}

// MergeOptions will merge two options giving preference to the flagOpts
// if the item is present.
func MergeOptions(fileOpts, flagOpts *Options) *Options {
	if fileOpts == nil {
		return flagOpts
	}
	if flagOpts == nil {
		return fileOpts
	}
	// Merge the two, flagOpts override
	opts := *fileOpts

	if flagOpts.Username != "" {
		opts.Username = flagOpts.Username
	}
	if flagOpts.Password != "" {
		opts.Password = flagOpts.Password
	}
	if flagOpts.Authorization != "" {
		opts.Authorization = flagOpts.Authorization
	}
	if flagOpts.HTTPBasePath != "" {
		opts.HTTPBasePath = flagOpts.HTTPBasePath
	}
	if flagOpts.Debug {
		opts.Debug = true
	}
	if flagOpts.Trace {
		opts.Trace = true
	}
	if flagOpts.Logtime {
		opts.Logtime = true
	}
	if flagOpts.Cluster.ConnectRetries != 0 {
		opts.Cluster.ConnectRetries = flagOpts.Cluster.ConnectRetries
	}
	return &opts
}

// RoutesFromStr parses route URLs from a string
func RoutesFromStr(routesStr string) []*url.URL {
	routes := strings.Split(routesStr, ",")
	if len(routes) == 0 {
		return nil
	}
	routeUrls := []*url.URL{}
	for _, r := range routes {
		r = strings.TrimSpace(r)
		u, _ := url.Parse(r)
		routeUrls = append(routeUrls, u)
	}
	return routeUrls
}

// RemoveSelfReference removes this server from an array of routes
func RemoveSelfReference(clusterPort int, routes []*url.URL) ([]*url.URL, error) {
	var cleanRoutes []*url.URL
	cport := strconv.Itoa(clusterPort)

	selfIPs, err := getInterfaceIPs()
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		host, port, err := net.SplitHostPort(r.Host)
		if err != nil {
			return nil, err
		}

		ipList, err := getURLIP(host)
		if err != nil {
			return nil, err
		}
		if cport == port && isIPInList(selfIPs, ipList) {
			continue
		}
		cleanRoutes = append(cleanRoutes, r)
	}

	return cleanRoutes, nil
}

func isIPInList(list1 []net.IP, list2 []net.IP) bool {
	for _, ip1 := range list1 {
		for _, ip2 := range list2 {
			if ip1.Equal(ip2) {
				return true
			}
		}
	}
	return false
}

func getURLIP(ipStr string) ([]net.IP, error) {
	ipList := []net.IP{}

	ip := net.ParseIP(ipStr)
	if ip != nil {
		ipList = append(ipList, ip)
		return ipList, nil
	}

	hostAddr, err := net.LookupHost(ipStr)
	if err != nil {
		return nil, fmt.Errorf("Error looking up host with route hostname: %v", err)
	}
	for _, addr := range hostAddr {
		ip = net.ParseIP(addr)
		if ip != nil {
			ipList = append(ipList, ip)
		}
	}
	return ipList, nil
}

func getInterfaceIPs() ([]net.IP, error) {
	var localIPs []net.IP

	interfaceAddr, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("Error getting self referencing address: %v", err)
	}

	for i := 0; i < len(interfaceAddr); i++ {
		interfaceIP, _, _ := net.ParseCIDR(interfaceAddr[i].String())
		if net.ParseIP(interfaceIP.String()) != nil {
			localIPs = append(localIPs, interfaceIP)
		} else {
			return nil, fmt.Errorf("Error parsing self referencing address: %v", err)
		}
	}
	return localIPs, nil
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
	if opts.AuthTimeout == 0 {
		opts.AuthTimeout = float64(AUTH_TIMEOUT) / float64(time.Second)
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

func normalizeBasePath(p string) string {
	if len(p) == 0 {
		return "/"
	}
	// add leading slash
	if p[0] != '/' {
		p = "/" + p
	}
	return path.Clean(p)
}

// overrideCluster updates Options.Cluster if that flag "cluster" (or "cluster_listen")
// has explicitly be set in the command line. If it is set to empty string, it will
// clear the Cluster options.
func overrideCluster(opts *Options) error {
	if opts.Cluster.Name == "" {
		// This one is enough to disable clustering.
		return nil
	}
	return nil
}

func processSignal(signal string) error {
	var (
		pid           string
		commandAndPid = strings.Split(signal, "=")
	)
	if l := len(commandAndPid); l == 2 {
		pid = maybeReadPidFile(commandAndPid[1])
	} else if l > 2 {
		return fmt.Errorf("invalid signal parameters: %v", commandAndPid[2:])
	}
	if err := ProcessSignal(Command(commandAndPid[0]), pid); err != nil {
		return err
	}
	os.Exit(0)
	return nil
}

// maybeReadPidFile returns a PID or Windows service name obtained via the following method:
// 1. Try to open a file with path "pidStr" (absolute or relative).
// 2. If such a file exists and can be read, return its contents.
// 3. Otherwise, return the original "pidStr" string.
func maybeReadPidFile(pidStr string) string {
	if b, err := ioutil.ReadFile(pidStr); err == nil {
		return string(b)
	}
	return pidStr
}

func homeDir() (string, error) {
	if runtime.GOOS == "windows" {
		homeDrive, homePath := os.Getenv("HOMEDRIVE"), os.Getenv("HOMEPATH")
		userProfile := os.Getenv("USERPROFILE")

		home := filepath.Join(homeDrive, homePath)
		if homeDrive == "" || homePath == "" {
			if userProfile == "" {
				return "", errors.New("nats: failed to get home dir, require %HOMEDRIVE% and %HOMEPATH% or %USERPROFILE%")
			}
			home = userProfile
		}

		return home, nil
	}

	home := os.Getenv("HOME")
	if home == "" {
		return "", errors.New("failed to get home dir, require $HOME")
	}
	return home, nil
}

func expandPath(p string) (string, error) {
	p = os.ExpandEnv(p)

	if !strings.HasPrefix(p, "~") {
		return p, nil
	}

	home, err := homeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, p[1:]), nil
}
