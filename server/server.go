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
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"

	// Allow dynamic profiling.
	_ "net/http/pprof"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nuid"

	"github.com/nats-io/nats-server/v2/logger"
)

const (
	// Interval for the first PING for non client connections.
	firstPingInterval = time.Second

	// This is for the first ping for client connections.
	firstClientPingInterval = 2 * time.Second
)

// Info is the information sent to clients, routes, gateways, and leaf nodes,
// to help them understand information about this server.
type Info struct {
	ID           string `json:"server_id"`
	Name         string `json:"server_name"`
	Version      string `json:"version"`
	Proto        int    `json:"proto"`
	GitCommit    string `json:"git_commit,omitempty"`
	GoVersion    string `json:"go"`
	Headers      bool   `json:"headers"`
	MaxPayload   int32  `json:"max_payload"`
	JetStream    bool   `json:"jetstream,omitempty"`
	CID          uint64 `json:"client_id,omitempty"`
	Nonce        string `json:"nonce,omitempty"`
	Cluster      string `json:"cluster,omitempty"`
	Dynamic      bool   `json:"cluster_dynamic,omitempty"`
	LameDuckMode bool   `json:"ldm,omitempty"`

	// Route Specific
	Import *SubjectPermission `json:"import,omitempty"`
	Export *SubjectPermission `json:"export,omitempty"`
	LNOC   bool               `json:"lnoc,omitempty"`

	// Gateways Specific
	Gateway           string `json:"gateway,omitempty"`             // Name of the origin Gateway (sent by gateway's INFO)
	GatewayCmd        byte   `json:"gateway_cmd,omitempty"`         // Command code for the receiving server to know what to do
	GatewayCmdPayload []byte `json:"gateway_cmd_payload,omitempty"` // Command payload when needed
	GatewayNRP        bool   `json:"gateway_nrp,omitempty"`         // Uses new $GNR. prefix for mapped replies
}

// Server is our main struct.
type Server struct {
	gcid uint64
	stats
	mu               sync.Mutex
	kp               nkeys.KeyPair
	prand            *rand.Rand
	info             Info
	optsMu           sync.RWMutex
	opts             *Options
	running          bool
	shutdown         bool
	reloading        bool
	gacc             *Account
	sys              *internal
	js               *jetStream
	accounts         sync.Map
	tmpAccounts      sync.Map // Temporarily stores accounts that are being built
	activeAccounts   int32
	accResolver      AccountResolver
	clients          map[uint64]*client
	routes           map[uint64]*client
	routesByHash     sync.Map
	hash             []byte
	remotes          map[string]*client
	leafs            map[uint64]*client
	nkeys            map[string]*NkeyUser
	totalClients     uint64
	closed           *closedRingBuffer
	done             chan bool
	start            time.Time
	httpHandler      http.Handler
	httpReqStats     map[string]uint64
	routeInfo        Info
	routeInfoJSON    []byte
	leafNodeInfo     Info
	leafNodeInfoJSON []byte

	quitCh           chan struct{}
	shutdownComplete chan struct{}

	// Tracking Go routines
	grMu         sync.Mutex
	grTmpClients map[uint64]*client
	grRunning    bool
	grWG         sync.WaitGroup // to wait on various go routines

	cproto     int64     // number of clients supporting async INFO
	configTime time.Time // last time config was loaded

	logging struct {
		sync.RWMutex
		logger      Logger
		trace       int32
		debug       int32
		traceSysAcc int32
	}

	lastCURLsUpdate int64

	// For Gateways
	gateway *srvGateway

	// Used by tests to check that http.Servers do
	// not set any timeout.
	monitoringServer *http.Server
	profilingServer  *http.Server

	// LameDuck mode
	ldm   bool
	ldmCh chan bool

	// We use this to minimize mem copies for requests to monitoring
	// endpoint /varz (when it comes from http).
	varzMu sync.Mutex
	varz   *Varz
	// This is set during a config reload if we detect that we have
	// added/removed routes. The monitoring code then check that
	// to know if it should update the cluster's URLs array.
	varzUpdateRouteURLs bool

	// Keeps a sublist of of subscriptions attached to leafnode connections
	// for the $GNR.*.*.*.> subject so that a server can send back a mapped
	// gateway reply.
	gwLeafSubs *Sublist

	// Used for expiration of mapped GW replies
	gwrm struct {
		w  int32
		ch chan time.Duration
		m  sync.Map
	}

	// For eventIDs
	eventIds *nuid.NUID
}

// Make sure all are 64bits for atomic use
type stats struct {
	inMsgs        int64
	outMsgs       int64
	inBytes       int64
	outBytes      int64
	slowConsumers int64
}

// NewServer constructs a new server struct with the given parameters.
// Could return an error if options can not be validated.
func NewServer(opts *Options, keyPair nkeys.KeyPair) (*Server, error) {
	setBaselineOptions(opts)

	// Created server's nkey identity.
	kp := keyPair
	pub, _ := kp.PublicKey()

	serverName := pub
	if opts.ServerName != "" {
		serverName = opts.ServerName
	}

	// Validate some options. This is here because we cannot assume that
	// server will always be started with configuration parsing (that could
	// report issues). Its options can be (incorrectly) set by hand when
	// server is embedded. If there is an error, return nil.
	if err := validateOptions(opts); err != nil {
		return nil, err
	}

	info := Info{
		ID:         pub,
		Version:    VERSION,
		Proto:      PROTO,
		GitCommit:  gitCommit,
		GoVersion:  runtime.Version(),
		Name:       serverName,
		MaxPayload: opts.MaxPayload,
		JetStream:  opts.JetStream,
		Headers:    !opts.NoHeaderSupport,
		Cluster:    opts.Cluster.Name,
	}

	now := time.Now()

	s := &Server{
		kp:         kp,
		info:       info,
		prand:      rand.New(rand.NewSource(time.Now().UnixNano())),
		opts:       opts,
		done:       make(chan bool, 1),
		start:      now,
		configTime: now,
		gwLeafSubs: NewSublistWithCache(),
		eventIds:   nuid.New(),
	}
	s.logging.logger = logger.NewLogger(opts.Logger, opts.Debug, opts.Trace, false)
	if opts.Debug {
		s.logging.debug = 1
	}
	if opts.Trace {
		s.logging.trace = 1
		s.logging.traceSysAcc = 1
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Call this even if there is no gateway defined. It will
	// initialize the structure so we don't have to check for
	// it to be nil or not in various places in the code.
	if err := s.newGateway(opts); err != nil {
		return nil, err
	}

	// If we have a cluster definition but do not have a cluster name, create one.
	if opts.Cluster.Name == "" {
		s.info.Cluster = nuid.Next()
	}

	// For tracking clients
	s.clients = make(map[uint64]*client)

	// For tracking closed clients.
	s.closed = newClosedRingBuffer(opts.MaxClosedClients)

	// For tracking connections that are not yet registered
	// in s.routes, but for which readLoop has started.
	s.grTmpClients = make(map[uint64]*client)

	// For tracking routes and their remote ids
	s.routes = make(map[uint64]*client)
	s.remotes = make(map[string]*client)

	// For tracking leaf nodes.
	s.leafs = make(map[uint64]*client)

	// Used to kick out all go routines possibly waiting on server
	// to shutdown.
	s.quitCh = make(chan struct{})
	// Closed when Shutdown() is complete. Allows WaitForShutdown() to block
	// waiting for complete shutdown.
	s.shutdownComplete = make(chan struct{})

	// Check for configured account resolvers.
	if err := s.configureResolver(); err != nil {
		return nil, err
	}
	// If there is an URL account resolver, do basic test to see if anyone is home.
	if ar := opts.AccountResolver; ar != nil {
		if ur, ok := ar.(*URLAccResolver); ok {
			if _, err := ur.Fetch(""); err != nil {
				return nil, err
			}
		}
	}

	// For tracking accounts
	if err := s.configureAccounts(); err != nil {
		return nil, err
	}

	// In local config mode, check that leafnode configuration
	// refers to account that exist.
	checkAccountExists := func(accName string) error {
		if accName == _EMPTY_ {
			return nil
		}
		if _, ok := s.accounts.Load(accName); !ok {
			return fmt.Errorf("cannot find account %q specified in leafnode authorization", accName)
		}
		return nil
	}
	if err := checkAccountExists(opts.LeafNode.Account); err != nil {
		return nil, err
	}
	for _, r := range opts.LeafNode.Remotes {
		if r.LocalAccount == _EMPTY_ {
			continue
		}
		if _, ok := s.accounts.Load(r.LocalAccount); !ok {
			return nil, fmt.Errorf("no local account %q for remote leafnode", r.LocalAccount)
		}
	}

	// Used to setup Authorization.
	s.configureAuthorization()

	return s, nil
}

// clusterName returns our cluster name which could be dynamic.
func (s *Server) ClusterName() string {
	s.mu.Lock()
	cn := s.info.Cluster
	s.mu.Unlock()
	return cn
}

// setClusterName will update the cluster name for this server.
func (s *Server) setClusterName(name string) {
	s.mu.Lock()
	var resetCh chan struct{}
	if s.sys != nil && s.info.Cluster != name {
		// can't hold the lock as go routine reading it may be waiting for lock as well
		resetCh = s.sys.resetCh
	}
	s.info.Cluster = name
	s.routeInfo.Cluster = name
	// Regenerate the info byte array
	s.generateRouteInfoJSON()
	// Need to close solicited leaf nodes. The close has to be done outside of the server lock.
	var leafs []*client
	for _, c := range s.leafs {
		c.mu.Lock()
		if c.leaf != nil && c.leaf.remote != nil {
			leafs = append(leafs, c)
		}
		c.mu.Unlock()
	}
	s.mu.Unlock()
	for _, l := range leafs {
		l.closeConnection(ClusterNameConflict)
	}
	if resetCh != nil {
		resetCh <- struct{}{}
	}
	s.Noticef("Cluster name updated to %s", name)

}

// Return whether the cluster name is dynamic.
func (s *Server) isClusterNameDynamic() bool {
	return s.getOpts().Cluster.Name == ""
}

func validateClusterName(o *Options) error {
	// Check that cluster name if defined matches any gateway name.
	if o.Gateway.Name != "" && o.Gateway.Name != o.Cluster.Name {
		if o.Cluster.Name != "" {
			return ErrClusterNameConfigConflict
		}
		// Set this here so we do not consider it dynamic.
		o.Cluster.Name = o.Gateway.Name
	}
	return nil
}

func validateOptions(o *Options) error {
	if o.LameDuckDuration > 0 && o.LameDuckGracePeriod >= o.LameDuckDuration {
		return fmt.Errorf("lame duck grace period (%v) should be strictly lower than lame duck duration (%v)",
			o.LameDuckGracePeriod, o.LameDuckDuration)
	}
	// Check on leaf nodes which will require a system
	// account when gateways are also configured.
	if err := validateLeafNode(o); err != nil {
		return err
	}
	// Check that gateway is properly configured. Returns no error
	// if there is no gateway defined.
	if err := validateGatewayOptions(o); err != nil {
		return err
	}
	// Check that cluster name if defined matches any gateway name.
	if err := validateClusterName(o); err != nil {
		return err
	}
	return nil
}

func (s *Server) getOpts() *Options {
	s.optsMu.RLock()
	opts := s.opts
	s.optsMu.RUnlock()
	return opts
}

func (s *Server) setOpts(opts *Options) {
	s.optsMu.Lock()
	s.opts = opts
	s.optsMu.Unlock()
}

func (s *Server) globalAccount() *Account {
	s.mu.Lock()
	gacc := s.gacc
	s.mu.Unlock()
	return gacc
}

// Used to setup Accounts.
// Lock is held upon entry.
func (s *Server) configureAccounts() error {
	// Create the global account.
	if s.gacc == nil {
		s.gacc = NewAccount(globalAccountName)
		s.registerAccountNoLock(s.gacc)
	}

	opts := s.opts

	// Check opts and walk through them. We need to copy them here
	// so that we do not keep a real one sitting in the options.
	for _, acc := range s.opts.Accounts {
		a := acc.shallowCopy()
		acc.sl = nil
		acc.clients = nil
		s.registerAccountNoLock(a)
	}

	// Now that we have this we need to remap any referenced accounts in
	// import or export maps to the new ones.
	swapApproved := func(ea *exportAuth) {
		for sub, a := range ea.approved {
			var acc *Account
			if v, ok := s.accounts.Load(a.Name); ok {
				acc = v.(*Account)
			}
			ea.approved[sub] = acc
		}
	}
	s.accounts.Range(func(k, v interface{}) bool {
		acc := v.(*Account)
		// Exports
		for _, se := range acc.exports.streams {
			if se != nil {
				swapApproved(&se.exportAuth)
			}
		}
		for _, se := range acc.exports.services {
			if se != nil {
				// Swap over the bound account for service exports.
				if se.acc != nil {
					if v, ok := s.accounts.Load(se.acc.Name); ok {
						se.acc = v.(*Account)
					}
				}
				swapApproved(&se.exportAuth)
			}
		}
		// Imports
		for _, si := range acc.imports.streams {
			if v, ok := s.accounts.Load(si.acc.Name); ok {
				si.acc = v.(*Account)
			}
		}
		for _, si := range acc.imports.services {
			if v, ok := s.accounts.Load(si.acc.Name); ok {
				si.acc = v.(*Account)
				si.se = si.acc.getServiceExport(si.to)
			}
		}
		// Make sure the subs are running, but only if not reloading.
		if len(acc.imports.services) > 0 && acc.ic == nil && !s.reloading {
			acc.ic = s.createInternalAccountClient()
			acc.ic.acc = acc
			acc.addAllServiceImportSubs()
		}

		return true
	})

	// Set the system account if it was configured.
	// Otherwise create a default one.
	if opts.SystemAccount != _EMPTY_ {
		// Lock may be acquired in lookupAccount, so release to call lookupAccount.
		s.mu.Unlock()
		acc, err := s.lookupAccount(opts.SystemAccount)
		s.mu.Lock()
		if err == nil && s.sys != nil && acc != s.sys.account {
			// sys.account.clients (including internal client)/respmap/etc... are transferred separately
			s.sys.account = acc
			s.mu.Unlock()
			// acquires server lock separately
			s.addSystemAccountExports(acc)
			s.mu.Lock()
		}
		if err != nil {
			return fmt.Errorf("error resolving system account: %v", err)
		}
	}

	return nil
}

// Setup the account resolver. For memory resolver, make sure the JWTs are
// properly formed but do not enforce expiration etc.
func (s *Server) configureResolver() error {
	opts := s.getOpts()
	s.accResolver = opts.AccountResolver
	if opts.AccountResolver != nil {
		// For URL resolver, set the TLSConfig if specified.
		if len(opts.resolverPreloads) > 0 {
			if s.accResolver.IsReadOnly() {
				return fmt.Errorf("resolver preloads only available for writeable resolver types MEM/DIR/CACHE_DIR")
			}
			for k, v := range opts.resolverPreloads {
				_, err := jwt.DecodeAccountClaims(v)
				if err != nil {
					return fmt.Errorf("preload account error for %q: %v", k, err)
				}
				s.accResolver.Store(k, v)
			}
		}
	}
	return nil
}

// This will check preloads for validation issues.
func (s *Server) checkResolvePreloads() {
	opts := s.getOpts()
	// We can just check the read-only opts versions here, that way we do not need
	// to grab server lock or access s.accResolver.
	for k, v := range opts.resolverPreloads {
		claims, err := jwt.DecodeAccountClaims(v)
		if err != nil {
			s.Errorf("Preloaded account [%s] not valid", k)
		}
		// Check if it is expired.
		vr := jwt.CreateValidationResults()
		claims.Validate(vr)
		if vr.IsBlocking(true) {
			s.Warnf("Account [%s] has validation issues:", k)
			for _, v := range vr.Issues {
				s.Warnf("  - %s", v.Description)
			}
		}
	}
}

func (s *Server) generateRouteInfoJSON() {
	b, _ := json.Marshal(s.routeInfo)
	pcs := [][]byte{[]byte("INFO"), b, []byte(CR_LF)}
	s.routeInfoJSON = bytes.Join(pcs, []byte(" "))
}

// Determines if we are in pre NATS 2.0 setup with no accounts.
func (s *Server) globalAccountOnly() bool {
	var hasOthers bool

	s.mu.Lock()
	s.accounts.Range(func(k, v interface{}) bool {
		acc := v.(*Account)
		// Ignore global and system
		if acc == s.gacc || (s.sys != nil && acc == s.sys.account) {
			return true
		}
		hasOthers = true
		return false
	})
	s.mu.Unlock()

	return !hasOthers
}

// Determines if this server is in standalone mode, meaning no routes or gateways or leafnodes.
func (s *Server) standAloneMode() bool {
	return false // TODO
}

// isTrustedIssuer will check that the issuer is a trusted public key.
// This is used to make sure an account was signed by a trusted operator.
func (s *Server) isTrustedIssuer(issuer string) bool {
	// s.mu.Lock()
	// defer s.mu.Unlock()
	// If we are not running in trusted mode and there is no issuer, that is ok.
	// if issuer == "" { return true }
	// TODO
	return true
}

// checkTrustedKeyString will check that the string is a valid array
// of public operator nkeys.
func checkTrustedKeyString(keys string) []string {
	tks := strings.Fields(keys)
	if len(tks) == 0 {
		return nil
	}
	// Walk all the keys and make sure they are valid.
	for _, key := range tks {
		if !nkeys.IsValidPublicOperatorKey(key) {
			return nil
		}
	}
	return tks
}

// ProcessCommandLineArgs takes the command line arguments
// validating and setting flags for handling in case any
// sub command was present.
func ProcessCommandLineArgs(cmd *flag.FlagSet) (showVersion bool, showHelp bool, err error) {
	if len(cmd.Args()) > 0 {
		arg := cmd.Args()[0]
		switch strings.ToLower(arg) {
		case "version":
			return true, false, nil
		case "help":
			return false, true, nil
		default:
			return false, false, fmt.Errorf("unrecognized command: %q", arg)
		}
	}

	return false, false, nil
}

// Protected check on running state
func (s *Server) isRunning() bool {
	s.mu.Lock()
	running := s.running
	s.mu.Unlock()
	return running
}

// NewAccountsAllowed returns whether or not new accounts can be created on the fly.
func (s *Server) NewAccountsAllowed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opts.AllowNewAccounts
}

// numReservedAccounts will return the number of reserved accounts configured in the server.
// Currently this is 1, one for the global default account.
func (s *Server) numReservedAccounts() int {
	return 1
}

// NumActiveAccounts reports number of active accounts on this server.
func (s *Server) NumActiveAccounts() int32 {
	return atomic.LoadInt32(&s.activeAccounts)
}

// incActiveAccounts() just adds one under lock.
func (s *Server) incActiveAccounts() {
	atomic.AddInt32(&s.activeAccounts, 1)
}

// decActiveAccounts() just subtracts one under lock.
func (s *Server) decActiveAccounts() {
	atomic.AddInt32(&s.activeAccounts, -1)
}

// This should be used for testing only. Will be slow since we have to
// range over all accounts in the sync.Map to count.
func (s *Server) numAccounts() int {
	count := 0
	s.mu.Lock()
	s.accounts.Range(func(k, v interface{}) bool {
		count++
		return true
	})
	s.mu.Unlock()
	return count
}

// NumLoadedAccounts returns the number of loaded accounts.
func (s *Server) NumLoadedAccounts() int {
	return s.numAccounts()
}

// LookupOrRegisterAccount will return the given account if known or create a new entry.
func (s *Server) LookupOrRegisterAccount(name string) (account *Account, isNew bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.accounts.Load(name); ok {
		return v.(*Account), false
	}
	acc := NewAccount(name)
	s.registerAccountNoLock(acc)
	return acc, true
}

// RegisterAccount will register an account. The account must be new
// or this call will fail.
func (s *Server) RegisterAccount(name string) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts.Load(name); ok {
		return nil, ErrAccountExists
	}
	acc := NewAccount(name)
	s.registerAccountNoLock(acc)
	return acc, nil
}

// SetSystemAccount will set the internal system account.
// If root operators are present it will also check validity.
func (s *Server) SetSystemAccount(accName string) error {
	// Lookup from sync.Map first.
	if v, ok := s.accounts.Load(accName); ok {
		return s.setSystemAccount(v.(*Account))
	}

	// If we are here we do not have local knowledge of this account.
	// Do this one by hand to return more useful error.
	ac, jwt, err := s.fetchAccountClaims(accName)
	if err != nil {
		return err
	}
	acc := s.buildInternalAccount(ac)
	acc.claimJWT = jwt
	// Due to race, we need to make sure that we are not
	// registering twice.
	if racc := s.registerAccount(acc); racc != nil {
		return nil
	}
	return s.setSystemAccount(acc)
}

// SystemAccount returns the system account if set.
func (s *Server) SystemAccount() *Account {
	var sacc *Account
	s.mu.Lock()
	if s.sys != nil {
		sacc = s.sys.account
	}
	s.mu.Unlock()
	return sacc
}

// GlobalAccount returns the global account.
// Default clients will use the global account.
func (s *Server) GlobalAccount() *Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gacc
}

// SetDefaultSystemAccount will create a default system account if one is not present.
func (s *Server) SetDefaultSystemAccount() error {
	if _, isNew := s.LookupOrRegisterAccount(DEFAULT_SYSTEM_ACCOUNT); !isNew {
		return nil
	}
	s.Debugf("Created system account: %q", DEFAULT_SYSTEM_ACCOUNT)
	return s.SetSystemAccount(DEFAULT_SYSTEM_ACCOUNT)
}

// For internal sends.
const internalSendQLen = 8192

// Assign a system account. Should only be called once.
// This sets up a server to send and receive messages from
// inside the server itself.
func (s *Server) setSystemAccount(acc *Account) error {
	if acc == nil {
		return ErrMissingAccount
	}
	// Don't try to fix this here.
	if acc.IsExpired() {
		return ErrAccountExpired
	}
	// If we are running with trusted keys for an operator
	// make sure we check the account is legit.
	if !s.isTrustedIssuer(acc.Issuer) {
		return ErrAccountValidation
	}

	s.mu.Lock()

	if s.sys != nil {
		s.mu.Unlock()
		return ErrAccountExists
	}

	// This is here in an attempt to quiet the race detector and not have to place
	// locks on fast path for inbound messages and checking service imports.
	acc.mu.Lock()
	if acc.imports.services == nil {
		acc.imports.services = make(map[string]*serviceImport)
	}
	acc.mu.Unlock()

	s.sys = &internal{
		account: acc,
		client:  s.createInternalSystemClient(),
		seq:     1,
		sid:     1,
		servers: make(map[string]*serverUpdate),
		replies: make(map[string]msgHandler),
		sendq:   make(chan *pubMsg, internalSendQLen),
		resetCh: make(chan struct{}),
		statsz:  eventsHBInterval,
		orphMax: 5 * eventsHBInterval,
		chkOrph: 3 * eventsHBInterval,
	}
	s.sys.wg.Add(1)
	s.mu.Unlock()

	// Register with the account.
	s.sys.client.registerWithAccount(acc)

	s.addSystemAccountExports(acc)

	// Start our internal loop to serialize outbound messages.
	// We do our own wg here since we will stop first during shutdown.
	go s.internalSendLoop(&s.sys.wg)

	// Start up our general subscriptions
	s.initEventTracking()

	// Track for dead remote servers.
	s.wrapChk(s.startRemoteServerSweepTimer)()

	// Send out statsz updates periodically.
	s.wrapChk(s.startStatszTimer)()

	// If we have existing accounts make sure we enable account tracking.
	s.mu.Lock()
	s.accounts.Range(func(k, v interface{}) bool {
		acc := v.(*Account)
		s.enableAccountTracking(acc)
		return true
	})
	s.mu.Unlock()

	return nil
}

// Creates an internal system client.
func (s *Server) createInternalSystemClient() *client {
	return s.createInternalClient(SYSTEM)
}

// Creates an internal jetstream client.
func (s *Server) createInternalJetStreamClient() *client {
	return s.createInternalClient(JETSTREAM)
}

// Creates an internal client for Account.
func (s *Server) createInternalAccountClient() *client {
	return s.createInternalClient(ACCOUNT)
}

// Internal clients. kind should be SYSTEM or JETSTREAM
func (s *Server) createInternalClient(kind int) *client {
	if kind != SYSTEM && kind != JETSTREAM && kind != ACCOUNT {
		return nil
	}
	now := time.Now()
	c := &client{srv: s, kind: kind, opts: internalOpts, msubs: -1, mpay: -1, start: now, last: now}
	c.initClient()
	c.echo = false
	c.headers = true
	c.flags.set(noReconnect)
	return c
}

// Determine if accounts should track subscriptions for
// efficient propagation.
// Lock should be held on entry.
func (s *Server) shouldTrackSubscriptions() bool {
	return (s.opts.Cluster.Name != "" || s.opts.Gateway.Name != "")
}

// Invokes registerAccountNoLock under the protection of the server lock.
// That is, server lock is acquired/released in this function.
// See registerAccountNoLock for comment on returned value.
func (s *Server) registerAccount(acc *Account) *Account {
	s.mu.Lock()
	racc := s.registerAccountNoLock(acc)
	s.mu.Unlock()
	return racc
}

// Helper to set the sublist based on preferences.
func (s *Server) setAccountSublist(acc *Account) {
	if acc != nil && acc.sl == nil {
		opts := s.getOpts()
		if opts != nil && opts.NoSublistCache {
			acc.sl = NewSublistNoCache()
		} else {
			acc.sl = NewSublistWithCache()
		}
	}
}

// Registers an account in the server.
// Due to some locking considerations, we may end-up trying
// to register the same account twice. This function will
// then return the already registered account.
// Lock should be held on entry.
func (s *Server) registerAccountNoLock(acc *Account) *Account {
	// We are under the server lock. Lookup from map, if present
	// return existing account.
	if a, _ := s.accounts.Load(acc.Name); a != nil {
		s.tmpAccounts.Delete(acc.Name)
		return a.(*Account)
	}
	// Finish account setup and store.
	s.setAccountSublist(acc)

	if acc.clients == nil {
		acc.clients = make(map[*client]struct{})
	}

	// If we are capable of routing we will track subscription
	// information for efficient interest propagation.
	// During config reload, it is possible that account was
	// already created (global account), so use locking and
	// make sure we create only if needed.
	acc.mu.Lock()
	// TODO(dlc)- Double check that we need this for GWs.
	if acc.rm == nil && s.opts != nil && s.shouldTrackSubscriptions() {
		acc.rm = make(map[string]int32)
		acc.lqws = make(map[string]int32)
	}
	acc.srv = s
	acc.mu.Unlock()
	s.accounts.Store(acc.Name, acc)
	s.tmpAccounts.Delete(acc.Name)
	s.enableAccountTracking(acc)
	return nil
}

// lookupAccount is a function to return the account structure
// associated with an account name.
// Lock MUST NOT be held upon entry.
func (s *Server) lookupAccount(name string) (*Account, error) {
	var acc *Account
	if v, ok := s.accounts.Load(name); ok {
		acc = v.(*Account)
	}
	if acc != nil {
		// If we are expired and we have a resolver, then
		// return the latest information from the resolver.
		if acc.IsExpired() {
			s.Debugf("Requested account [%s] has expired", name)
			if s.AccountResolver() != nil {
				if err := s.updateAccount(acc); err != nil {
					// This error could mask expired, so just return expired here.
					return nil, ErrAccountExpired
				}
			} else {
				return nil, ErrAccountExpired
			}
		}
		return acc, nil
	}
	// If we have a resolver see if it can fetch the account.
	if s.AccountResolver() == nil {
		return nil, ErrMissingAccount
	}
	return s.fetchAccount(name)
}

// LookupAccount is a public function to return the account structure
// associated with name.
func (s *Server) LookupAccount(name string) (*Account, error) {
	return s.lookupAccount(name)
}

// This will fetch new claims and if found update the account with new claims.
// Lock MUST NOT be held upon entry.
func (s *Server) updateAccount(acc *Account) error {
	// TODO(dlc) - Make configurable
	if time.Since(acc.updated) < time.Second {
		s.Debugf("Requested account update for [%s] ignored, too soon", acc.Name)
		return ErrAccountResolverUpdateTooSoon
	}
	claimJWT, err := s.fetchRawAccountClaims(acc.Name)
	if err != nil {
		return err
	}
	return s.updateAccountWithClaimJWT(acc, claimJWT)
}

// updateAccountWithClaimJWT will check and apply the claim update.
// Lock MUST NOT be held upon entry.
func (s *Server) updateAccountWithClaimJWT(acc *Account, claimJWT string) error {
	if acc == nil {
		return ErrMissingAccount
	}
	acc.updated = time.Now()
	if acc.claimJWT != "" && acc.claimJWT == claimJWT {
		s.Debugf("Requested account update for [%s], same claims detected", acc.Name)
		return ErrAccountResolverSameClaims
	}
	accClaims, _, err := s.verifyAccountClaims(claimJWT)
	if err == nil && accClaims != nil {
		acc.mu.Lock()
		if acc.Issuer == "" {
			acc.Issuer = accClaims.Issuer
		} else if acc.Issuer != accClaims.Issuer {
			acc.mu.Unlock()
			return ErrAccountValidation
		}
		acc.claimJWT = claimJWT
		acc.mu.Unlock()
		s.UpdateAccountClaims(acc, accClaims)
		return nil
	}
	return err
}

// fetchRawAccountClaims will grab raw account claims iff we have a resolver.
// Lock is NOT held upon entry.
func (s *Server) fetchRawAccountClaims(name string) (string, error) {
	accResolver := s.AccountResolver()
	if accResolver == nil {
		return "", ErrNoAccountResolver
	}
	// Need to do actual Fetch
	start := time.Now()
	claimJWT, err := accResolver.Fetch(name)
	fetchTime := time.Since(start)
	if fetchTime > time.Second {
		s.Warnf("Account [%s] fetch took %v", name, fetchTime)
	} else {
		s.Debugf("Account [%s] fetch took %v", name, fetchTime)
	}
	if err != nil {
		s.Warnf("Account fetch failed: %v", err)
		return "", err
	}
	return claimJWT, nil
}

// fetchAccountClaims will attempt to fetch new claims if a resolver is present.
// Lock is NOT held upon entry.
func (s *Server) fetchAccountClaims(name string) (*jwt.AccountClaims, string, error) {
	claimJWT, err := s.fetchRawAccountClaims(name)
	if err != nil {
		return nil, _EMPTY_, err
	}
	return s.verifyAccountClaims(claimJWT)
}

// verifyAccountClaims will decode and validate any account claims.
func (s *Server) verifyAccountClaims(claimJWT string) (*jwt.AccountClaims, string, error) {
	accClaims, err := jwt.DecodeAccountClaims(claimJWT)
	if err != nil {
		return nil, _EMPTY_, err
	}
	vr := jwt.CreateValidationResults()
	accClaims.Validate(vr)
	if vr.IsBlocking(true) {
		return nil, _EMPTY_, ErrAccountValidation
	}
	if !s.isTrustedIssuer(accClaims.Issuer) {
		return nil, _EMPTY_, ErrAccountValidation
	}
	return accClaims, claimJWT, nil
}

// This will fetch an account from a resolver if defined.
// Lock is NOT held upon entry.
func (s *Server) fetchAccount(name string) (*Account, error) {
	accClaims, claimJWT, err := s.fetchAccountClaims(name)
	if accClaims == nil {
		return nil, err
	}
	acc := s.buildInternalAccount(accClaims)
	acc.claimJWT = claimJWT
	// Due to possible race, if registerAccount() returns a non
	// nil account, it means the same account was already
	// registered and we should use this one.
	if racc := s.registerAccount(acc); racc != nil {
		// Update with the new claims in case they are new.
		// Following call will ignore ErrAccountResolverSameClaims
		// if claims are the same.
		err = s.updateAccountWithClaimJWT(racc, claimJWT)
		if err != nil && err != ErrAccountResolverSameClaims {
			return nil, err
		}
		return racc, nil
	}
	// The sub imports may have been setup but will not have had their
	// subscriptions properly setup. Do that here.
	if len(acc.imports.services) > 0 && acc.ic == nil {
		acc.ic = s.createInternalAccountClient()
		acc.ic.acc = acc
		acc.addAllServiceImportSubs()
	}
	return acc, nil
}

// Start up the server, this will block.
// Start via a Go routine if needed.
func (s *Server) Start() {
	s.Noticef("Starting nats-server version %s", VERSION)
	s.Debugf("Go build version %s", s.info.GoVersion)

	// Avoid RACE between Start() and Shutdown()
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	s.grMu.Lock()
	s.grRunning = true
	s.grMu.Unlock()

	// Snapshot server options.
	opts := s.getOpts()

	// Setup system account which will start the eventing stack.
	if sa := opts.SystemAccount; sa != _EMPTY_ {
		if err := s.SetSystemAccount(sa); err != nil {
			s.Fatalf("Can't set system account: %v", err)
			return
		}
	} else if !opts.NoSystemAccount {
		// We will create a default system account here.
		s.SetDefaultSystemAccount()
	}

	// start up resolver machinery
	if ar := s.AccountResolver(); ar != nil {
		if err := ar.Start(s); err != nil {
			s.Fatalf("Could not start resolver: %v", err)
			return
		}
	}

	// Start expiration of mapped GW replies, regardless if
	// this server is configured with gateway or not.
	s.startGWReplyMapExpiration()

	// Check if JetStream has been enabled. This needs to be after
	// the system account setup above. JetStream will create its
	// own system account if one is not present.
	if opts.JetStream {
		// Make sure someone is not trying to enable on the system account.
		if sa := s.SystemAccount(); sa != nil && sa.jsLimits != nil {
			s.Fatalf("Not allowed to enable JetStream on the system account")
		}
		cfg := &JetStreamConfig{
			StoreDir:  opts.StoreDir,
			MaxMemory: opts.JetStreamMaxMemory,
			MaxStore:  opts.JetStreamMaxStore,
		}
		if err := s.EnableJetStream(cfg); err != nil {
			s.Fatalf("Can't start JetStream: %v", err)
			return
		}
	} else {
		// Check to see if any configured accounts have JetStream enabled
		// and warn if they do.
		s.accounts.Range(func(k, v interface{}) bool {
			acc := v.(*Account)
			acc.mu.RLock()
			hasJs := acc.jsLimits != nil
			name := acc.Name
			acc.mu.RUnlock()
			if hasJs {
				s.Warnf("Account [%q] has JetStream configuration but JetStream not enabled", name)
			}
			return true
		})
	}

	// Start monitoring if needed
	if err := s.StartMonitoring(); err != nil {
		s.Fatalf("Can't start monitoring: %v", err)
		return
	}

	// Start up gateway if needed. Do this before starting the routes, because
	// we want to resolve the gateway host:port so that this information can
	// be sent to other routes.
	if opts.Gateway.Name != "" {
		s.startGateways()
	}

	// Start up listen if we want to accept leaf node connections.
	// if !opts.LeafNode.NoAdvertise { // != "" {
	// Will resolve or assign the advertise address for the leafnode listener.
	// We need that in StartRouting().
	s.startLeafNodeAcceptLoop()
	// }

	// Solicit remote servers for leaf node connections.
	if len(opts.LeafNode.Remotes) > 0 {
		s.solicitLeafNodeRemotes(opts.LeafNode.Remotes)
	}

	// TODO (ik): I wanted to refactor this by starting the client
	// accept loop first, that is, it would resolve listen spec
	// in place, but start the accept-for-loop in a different go
	// routine. This would get rid of the synchronization between
	// this function and StartRouting, which I also would have wanted
	// to refactor, but both AcceptLoop() and StartRouting() have
	// been exported and not sure if that would break users using them.
	// We could mark them as deprecated and remove in a release or two...

	// The Routing routine needs to wait for the client listen
	// port to be opened and potential ephemeral port selected.
	clientListenReady := make(chan struct{})

	// Start websocket server if needed. Do this before starting the routes,
	// because we want to resolve the gateway host:port so that this information
	// can be sent to other routes.
	/*
		if opts.Websocket.Port != 0 {
			s.startWebsocketServer()
		}
	*/

	// Start up routing as well if needed.
	if opts.Cluster.Name != "" {
		s.startGoRoutine(func() {
			s.StartRouting(clientListenReady)
		})
	}

	// Wait for clients.
	s.AcceptLoop(clientListenReady)
}

// Shutdown will shutdown the server instance by kicking out the AcceptLoop
// and closing all associated clients.
func (s *Server) Shutdown() {
	// Shutdown the eventing system as needed.
	// This is done first to send out any messages for
	// account status. We will also clean up any
	// eventing items associated with accounts.
	s.shutdownEventing()

	// Now check jetstream.
	s.shutdownJetStream()

	s.mu.Lock()
	// Prevent issues with multiple calls.
	if s.shutdown {
		s.mu.Unlock()
		return
	}
	s.Noticef("Initiating Shutdown...")

	if s.accResolver != nil {
		s.accResolver.Close()
	}

	opts := s.getOpts()
	_ = opts

	s.shutdown = true
	s.running = false
	s.grMu.Lock()
	s.grRunning = false
	s.grMu.Unlock()

	conns := make(map[uint64]*client)

	// Copy off the clients
	for i, c := range s.clients {
		conns[i] = c
	}
	// Copy off the connections that are not yet registered
	// in s.routes, but for which the readLoop has started
	s.grMu.Lock()
	for i, c := range s.grTmpClients {
		conns[i] = c
	}
	s.grMu.Unlock()
	// Copy off the routes
	for i, r := range s.routes {
		conns[i] = r
	}
	// Copy off the gateways
	s.getAllGatewayConnections(conns)

	// Copy off the leaf nodes
	for i, c := range s.leafs {
		conns[i] = c
	}

	// Number of done channel responses we expect.
	doneExpected := 0

	s.mu.Unlock()

	// Release go routines that wait on that channel
	close(s.quitCh)

	// Close client and route connections
	for _, c := range conns {
		c.setNoReconnect()
		c.closeConnection(ServerShutdown)
	}

	// Block until the accept loops exit
	for doneExpected > 0 {
		<-s.done
		doneExpected--
	}

	// Wait for go routines to be done.
	s.grWG.Wait()

	s.Noticef("Server Exiting..")
	// Close logger if applicable. It allows tests on Windows
	// to be able to do proper cleanup (delete log file).
	s.logging.RLock()
	log := s.logging.logger
	s.logging.RUnlock()
	if log != nil {
		if l, ok := log.(*logger.Logger); ok {
			l.Close()
		}
	}
	// Notify that the shutdown is complete
	close(s.shutdownComplete)
}

// WaitForShutdown will block until the server has been fully shutdown.
func (s *Server) WaitForShutdown() {
	<-s.shutdownComplete
}

// AcceptLoop is exported for easier testing.
func (s *Server) AcceptLoop(clr chan struct{}) {
	// If we were to exit before the listener is setup properly,
	// make sure we close the channel.
	defer func() {
		if clr != nil {
			close(clr)
		}
	}()

	// Snapshot server options.
	// opts := s.getOpts()

	// Setup state that can enable shutdown
	s.mu.Lock()
	if s.shutdown {
		s.mu.Unlock()
		return
	}

	s.Noticef("Listening for client connections on internal mux")
	s.Noticef("Server id is %s", s.info.ID)
	s.Noticef("Server is ready")

	s.mu.Unlock()

	// Let the caller know that we are ready
	close(clr)
	clr = nil
}

// HandleClientConnection handles an incoming client session with a nkey public key.
func (s *Server) HandleClientConnection(conn net.Conn, identNkey string) *client {
	return s.createClient(conn, identNkey)
}

// StartMonitoring starts the HTTP or HTTPs server if needed.
func (s *Server) StartMonitoring() error {
	// Snapshot server options.
	// opts := s.getOpts()

	var err error
	err = s.startMonitoring(false)
	return err
}

// HTTP endpoints
const (
	RootPath     = "/"
	VarzPath     = "/varz"
	ConnzPath    = "/connz"
	RoutezPath   = "/routez"
	GatewayzPath = "/gatewayz"
	LeafzPath    = "/leafz"
	SubszPath    = "/subsz"
	StackszPath  = "/stacksz"
)

// Start the monitoring server
func (s *Server) startMonitoring(secure bool) error {
	// Snapshot server options.
	// opts := s.getOpts()

	// Used to track HTTP requests
	s.httpReqStats = map[string]uint64{
		RootPath:     0,
		VarzPath:     0,
		ConnzPath:    0,
		RoutezPath:   0,
		GatewayzPath: 0,
		SubszPath:    0,
	}

	var hp string

	s.Noticef("Starting http monitor on internal mux")
	mux := http.NewServeMux()

	// Root
	mux.HandleFunc((RootPath), s.HandleRoot)
	// Varz
	mux.HandleFunc((VarzPath), s.HandleVarz)
	// Connz
	mux.HandleFunc((ConnzPath), s.HandleConnz)
	// Routez
	mux.HandleFunc((RoutezPath), s.HandleRoutez)
	// Gatewayz
	mux.HandleFunc((GatewayzPath), s.HandleGatewayz)
	// Leafz
	mux.HandleFunc((LeafzPath), s.HandleLeafz)
	// Subz
	mux.HandleFunc((SubszPath), s.HandleSubsz)
	// Subz alias for backwards compatibility
	mux.HandleFunc(("/subscriptionsz"), s.HandleSubsz)
	// Stacksz
	mux.HandleFunc((StackszPath), s.HandleStacksz)

	// Do not set a WriteTimeout because it could cause cURL/browser
	// to return empty response or unable to display page if the
	// server needs more time to build the response.
	srv := &http.Server{
		Addr:           hp,
		Handler:        mux,
		MaxHeaderBytes: 1 << 20,
	}
	s.mu.Lock()
	s.httpHandler = mux
	s.monitoringServer = srv
	s.mu.Unlock()

	return nil
}

// HTTPHandler returns the http.Handler object used to handle monitoring
// endpoints. It will return nil if the server is not configured for
// monitoring, or if the server has not been started yet (Server.Start()).
func (s *Server) HTTPHandler() http.Handler {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.httpHandler
}

// Perform a conditional deep copy due to reference nature of [Client|WS]ConnectURLs.
// If updates are made to Info, this function should be consulted and updated.
// Assume lock is held.
func (s *Server) copyInfo() Info {
	info := s.info
	return info
}

// tlsMixConn is used when we can receive both TLS and non-TLS connections on same port.
type tlsMixConn struct {
	net.Conn
	pre *bytes.Buffer
}

// Read for our mixed multi-reader.
func (c *tlsMixConn) Read(b []byte) (int, error) {
	if c.pre != nil {
		n, err := c.pre.Read(b)
		if c.pre.Len() == 0 {
			c.pre = nil
		}
		return n, err
	}
	return c.Conn.Read(b)
}

// createClient builds a client with a connection and nkey public key
func (s *Server) createClient(conn net.Conn, identNkey string) *client {
	// Snapshot server options.
	opts := s.getOpts()

	maxPay := int32(opts.MaxPayload)
	maxSubs := int32(opts.MaxSubs)
	// For system, maxSubs of 0 means unlimited, so re-adjust here.
	if maxSubs == 0 {
		maxSubs = -1
	}
	now := time.Now()

	c := &client{srv: s, nc: conn, opts: defaultOpts, mpay: maxPay, msubs: maxSubs, start: now, last: now}

	c.registerWithAccount(s.globalAccount())

	// Grab JSON info string
	s.mu.Lock()
	info := s.copyInfo()
	// Nonce handling
	var raw [nonceLen]byte
	nonce := raw[:]
	s.generateNonce(nonce)
	info.Nonce = string(nonce)
	c.nonce = []byte(info.Nonce)
	s.totalClients++
	s.mu.Unlock()

	// Grab lock
	c.mu.Lock()

	// if auth required -> set expectConnect flag
	// c.flags.set(expectConnect)

	// Initialize
	if identNkey != "" {
		c.opts.Nkey = identNkey
	}
	c.initClient()

	c.Debugf("Client connection created")

	// Send our information.
	// Need to be sent in place since writeLoop cannot be started until
	// TLS handshake is done (if applicable).
	c.sendProtoNow(c.generateClientInfoJSON(info))

	// Unlock to register
	c.mu.Unlock()

	// Register with the server.
	s.mu.Lock()
	// If server is not running, Shutdown() may have already gathered the
	// list of connections to close. It won't contain this one, so we need
	// to bail out now otherwise the readLoop started down there would not
	// be interrupted. Skip also if in lame duck mode.
	if !s.running || s.ldm {
		// There are some tests that create a server but don't start it,
		// and use "async" clients and perform the parsing manually. Such
		// clients would branch here (since server is not running). However,
		// when a server was really running and has been shutdown, we must
		// close this connection.
		if s.shutdown {
			conn.Close()
		}
		s.mu.Unlock()
		return c
	}

	// If there is a max connections specified, check that adding
	// this new client would not push us over the max
	if opts.MaxConn > 0 && len(s.clients) >= opts.MaxConn {
		s.mu.Unlock()
		c.maxConnExceeded()
		return nil
	}
	s.clients[c.cid] = c
	s.mu.Unlock()

	// Re-Grab lock
	c.mu.Lock()

	// Connection could have been closed while sending the INFO proto.
	isClosed := c.isClosed()
	var pre []byte

	// If connection is marked as closed, bail out.
	if isClosed {
		c.mu.Unlock()
		// Connection could have been closed due to TLS timeout or while trying
		// to send the INFO protocol. We need to call closeConnection() to make
		// sure that proper cleanup is done.
		c.closeConnection(WriteError)
		return nil
	}

	// Check for Auth. We schedule this timer after the TLS handshake to avoid
	// the race where the timer fires during the handshake and causes the
	// server to write bad data to the socket. See issue #432.
	/*
		if info.AuthRequired {
			timeout := opts.AuthTimeout
			c.setAuthTimer(secondsToDuration(timeout))
		}
	*/

	// Spin up the read loop.
	s.startGoRoutine(func() { c.readLoop(pre) })

	// Spin up the write loop.
	s.startGoRoutine(func() { c.writeLoop() })

	c.mu.Unlock()

	return c
}

// This will save off a closed client in a ring buffer such that
// /connz can inspect. Useful for debugging, etc.
func (s *Server) saveClosedClient(c *client, nc net.Conn, reason ClosedState) {
	now := time.Now()

	s.accountDisconnectEvent(c, now, reason.String())

	c.mu.Lock()

	cc := &closedClient{}
	cc.fill(c, nc, now)
	cc.Stop = &now
	cc.Reason = reason.String()

	// Do subs, do not place by default in main ConnInfo
	if len(c.subs) > 0 {
		cc.subs = make([]SubDetail, 0, len(c.subs))
		for _, sub := range c.subs {
			cc.subs = append(cc.subs, newSubDetail(sub))
		}
	}
	// Hold account name if not the global account.
	if c.acc != nil && c.acc.Name != globalAccountName {
		cc.acc = c.acc.Name
	}
	c.mu.Unlock()

	// Place in the ring buffer
	s.mu.Lock()
	if s.closed != nil {
		s.closed.append(cc)
	}
	s.mu.Unlock()
}

// Remove a client or route from our internal accounting.
func (s *Server) removeClient(c *client) {
	// kind is immutable, so can check without lock
	switch c.kind {
	case CLIENT:
		c.mu.Lock()
		cid := c.cid
		updateProtoInfoCount := false
		if c.kind == CLIENT && c.opts.Protocol >= ClientProtoInfo {
			updateProtoInfoCount = true
		}
		c.mu.Unlock()

		s.mu.Lock()
		delete(s.clients, cid)
		if updateProtoInfoCount {
			s.cproto--
		}
		s.mu.Unlock()
	case ROUTER:
		s.removeRoute(c)
	case GATEWAY:
		s.removeRemoteGatewayConnection(c)
	case LEAF:
		s.removeLeafNodeConnection(c)
	}
}

func (s *Server) removeFromTempClients(cid uint64) {
	s.grMu.Lock()
	delete(s.grTmpClients, cid)
	s.grMu.Unlock()
}

func (s *Server) addToTempClients(cid uint64, c *client) bool {
	added := false
	s.grMu.Lock()
	if s.grRunning {
		s.grTmpClients[cid] = c
		added = true
	}
	s.grMu.Unlock()
	return added
}

/////////////////////////////////////////////////////////////////
// These are some helpers for accounting in functional tests.
/////////////////////////////////////////////////////////////////

// NumRoutes will report the number of registered routes.
func (s *Server) NumRoutes() int {
	s.mu.Lock()
	nr := len(s.routes)
	s.mu.Unlock()
	return nr
}

// NumRemotes will report number of registered remotes.
func (s *Server) NumRemotes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.remotes)
}

// NumLeafNodes will report number of leaf node connections.
func (s *Server) NumLeafNodes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.leafs)
}

// NumClients will report the number of registered clients.
func (s *Server) NumClients() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients)
}

// GetClient will return the client associated with cid.
func (s *Server) GetClient(cid uint64) *client {
	return s.getClient(cid)
}

// getClient will return the client associated with cid.
func (s *Server) getClient(cid uint64) *client {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clients[cid]
}

// GetLeafNode returns the leafnode associated with the cid.
func (s *Server) GetLeafNode(cid uint64) *client {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.leafs[cid]
}

// NumSubscriptions will report how many subscriptions are active.
func (s *Server) NumSubscriptions() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.numSubscriptions()
}

// numSubscriptions will report how many subscriptions are active.
// Lock should be held.
func (s *Server) numSubscriptions() uint32 {
	var subs int
	s.accounts.Range(func(k, v interface{}) bool {
		acc := v.(*Account)
		if acc.sl != nil {
			subs += acc.TotalSubs()
		}
		return true
	})
	return uint32(subs)
}

// NumSlowConsumers will report the number of slow consumers.
func (s *Server) NumSlowConsumers() int64 {
	return atomic.LoadInt64(&s.slowConsumers)
}

// ConfigTime will report the last time the server configuration was loaded.
func (s *Server) ConfigTime() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.configTime
}

// ReadyForConnections returns `true` if the server is ready to accept clients
// and, if routing is enabled, route connections. If after the duration
// `dur` the server is still not ready, returns `false`.
func (s *Server) ReadyForConnections(dur time.Duration) bool {
	return true
}

// Quick utility to function to tell if the server supports headers.
func (s *Server) supportsHeaders() bool {
	if s == nil {
		return false
	}
	return !(s.getOpts().NoHeaderSupport)
}

// ID returns the server's ID
func (s *Server) ID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info.ID
}

// Name returns the server's name. This will be the same as the ID if it was not set.
func (s *Server) Name() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info.Name
}

func (s *Server) startGoRoutine(f func()) bool {
	var started bool
	s.grMu.Lock()
	if s.grRunning {
		s.grWG.Add(1)
		go f()
		started = true
	}
	s.grMu.Unlock()
	return started
}

func (s *Server) numClosedConns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed.len()
}

func (s *Server) totalClosedConns() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed.totalConns()
}

func (s *Server) closedClients() []*closedClient {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed.closedClients()
}

// Generic version that will return an array of URLs based on the given
// advertise, host and port values.
func (s *Server) getConnectURLs(advertise, host string, port int) ([]string, error) {
	urls := make([]string, 0, 1)

	// short circuit if advertise is set
	if advertise != "" {
		h, p, err := parseHostPort(advertise, port)
		if err != nil {
			return nil, err
		}
		urls = append(urls, net.JoinHostPort(h, strconv.Itoa(p)))
	} else {
		sPort := strconv.Itoa(port)
		_, ips, err := s.getNonLocalIPsIfHostIsIPAny(host, true)
		for _, ip := range ips {
			urls = append(urls, net.JoinHostPort(ip, sPort))
		}
		if err != nil || len(urls) == 0 {
			// We are here if s.opts.Host is not "0.0.0.0" nor "::", or if for some
			// reason we could not add any URL in the loop above.
			// We had a case where a Windows VM was hosed and would have err == nil
			// and not add any address in the array in the loop above, and we
			// ended-up returning 0.0.0.0, which is problematic for Windows clients.
			// Check for 0.0.0.0 or :: specifically, and ignore if that's the case.
			if host == "0.0.0.0" || host == "::" {
				s.Errorf("Address %q can not be resolved properly", host)
			} else {
				urls = append(urls, net.JoinHostPort(host, sPort))
			}
		}
	}
	return urls, nil
}

// Returns an array of non local IPs if the provided host is
// 0.0.0.0 or ::. It returns the first resolved if `all` is
// false.
// The boolean indicate if the provided host was 0.0.0.0 (or ::)
// so that if the returned array is empty caller can decide
// what to do next.
func (s *Server) getNonLocalIPsIfHostIsIPAny(host string, all bool) (bool, []string, error) {
	ip := net.ParseIP(host)
	// If this is not an IP, we are done
	if ip == nil {
		return false, nil, nil
	}
	// If this is not 0.0.0.0 or :: we have nothing to do.
	if !ip.IsUnspecified() {
		return false, nil, nil
	}
	s.Debugf("Get non local IPs for %q", host)
	var ips []string
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ipStr := ip.String()
			// Skip non global unicast addresses
			if !ip.IsGlobalUnicast() || ip.IsUnspecified() {
				ip = nil
				continue
			}
			s.Debugf("  ip=%s", ipStr)
			ips = append(ips, ipStr)
			if !all {
				break
			}
		}
	}
	return true, ips, nil
}

// Ports describes URLs that the server can be contacted in
type Ports struct {
	Nats       []string `json:"nats,omitempty"`
	Monitoring []string `json:"monitoring,omitempty"`
	Cluster    []string `json:"cluster,omitempty"`
	Profile    []string `json:"profile,omitempty"`
	WebSocket  []string `json:"websocket,omitempty"`
}

// PortsInfo attempts to resolve all the ports. If after maxWait the ports are not
// resolved, it returns nil. Otherwise it returns a Ports struct
// describing ports where the server can be contacted
func (s *Server) PortsInfo(maxWait time.Duration) *Ports {
	ports := Ports{}
	// TODO aperture-2.x: determine ports to specify?
	return &ports
}

// waits until a calculated list of listeners is resolved or a timeout
func (s *Server) readyForListeners(dur time.Duration) bool {
	return true
}

// Returns true if in lame duck mode.
func (s *Server) isLameDuckMode() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ldm
}

// This function will close the client listener then close the clients
// at some interval to avoid a reconnecting storm.
func (s *Server) lameDuckMode() {
	s.mu.Lock()
	// Check if there is actually anything to do
	if s.shutdown || s.ldm {
		s.mu.Unlock()
		return
	}
	s.Noticef("Entering lame duck mode, stop accepting new clients")
	s.ldm = true
	expected := 1
	s.ldmCh = make(chan bool, expected)
	opts := s.getOpts()
	gp := opts.LameDuckGracePeriod
	// For tests, we want the grace period to be in some cases bigger
	// than the ldm duration, so to by-pass the validateOptions() check,
	// we use negative number and flip it here.
	if gp < 0 {
		gp *= -1
	}
	s.mu.Unlock()

	// Wait for accept loops to be done to make sure that no new
	// client can connect
	for i := 0; i < expected; i++ {
		<-s.ldmCh
	}

	s.mu.Lock()
	// Need to recheck few things
	if s.shutdown || len(s.clients) == 0 {
		s.mu.Unlock()
		// If there is no client, we need to call Shutdown() to complete
		// the LDMode. If server has been shutdown while lock was released,
		// calling Shutdown() should be no-op.
		s.Shutdown()
		return
	}
	dur := int64(opts.LameDuckDuration)
	dur -= int64(gp)
	if dur <= 0 {
		dur = int64(time.Second)
	}
	numClients := int64(len(s.clients))
	batch := 1
	// Sleep interval between each client connection close.
	si := dur / numClients
	if si < 1 {
		// Should not happen (except in test with very small LD duration), but
		// if there are too many clients, batch the number of close and
		// use a tiny sleep interval that will result in yield likely.
		si = 1
		batch = int(numClients / dur)
	} else if si > int64(time.Second) {
		// Conversely, there is no need to sleep too long between clients
		// and spread say 10 clients for the 2min duration. Sleeping no
		// more than 1sec.
		si = int64(time.Second)
	}

	// Now capture all clients
	clients := make([]*client, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}
	// Now that we know that no new client can be accepted,
	// send INFO to routes and clients to notify this state.
	s.sendLDMToRoutes()
	s.sendLDMToClients()
	s.mu.Unlock()

	t := time.NewTimer(gp)
	// Delay start of closing of client connections in case
	// we have several servers that we want to signal to enter LD mode
	// and not have their client reconnect to each other.
	select {
	case <-t.C:
		s.Noticef("Closing existing clients")
	case <-s.quitCh:
		t.Stop()
		return
	}
	for i, client := range clients {
		client.closeConnection(ServerShutdown)
		if i == len(clients)-1 {
			break
		}
		if batch == 1 || i%batch == 0 {
			// We pick a random interval which will be at least si/2
			v := rand.Int63n(si)
			if v < si/2 {
				v = si / 2
			}
			t.Reset(time.Duration(v))
			// Sleep for given interval or bail out if kicked by Shutdown().
			select {
			case <-t.C:
			case <-s.quitCh:
				t.Stop()
				return
			}
		}
	}
	s.Shutdown()
}

// Send an INFO update to routes with the indication that this server is in LDM mode.
// Server lock is held on entry.
func (s *Server) sendLDMToRoutes() {
	s.routeInfo.LameDuckMode = true
	s.generateRouteInfoJSON()
	for _, r := range s.routes {
		r.mu.Lock()
		r.enqueueProto(s.routeInfoJSON)
		r.mu.Unlock()
	}
	// Clear now so that we notify only once, should we have to send other INFOs.
	s.routeInfo.LameDuckMode = false
}

// Send an INFO update to clients with the indication that this server is in
// LDM mode and with only URLs of other nodes.
// Server lock is held on entry.
func (s *Server) sendLDMToClients() {
	s.info.LameDuckMode = true
	// Clear this so that if there are further updates, we don't send our URLs.
	// s.clientConnectURLs = s.clientConnectURLs[:0]
	/*
		if s.websocket.connectURLs != nil {
			s.websocket.connectURLs = s.websocket.connectURLs[:0]
		}
	*/
	// Reset content first.
	/*
		s.info.ClientConnectURLs = s.info.ClientConnectURLs[:0]
		s.info.WSConnectURLs = s.info.WSConnectURLs[:0]
	*/
	// Only add the other nodes if we are allowed to.
	/*
		if !s.getOpts().Cluster.NoAdvertise {
			for url := range s.clientConnectURLsMap {
				s.info.ClientConnectURLs = append(s.info.ClientConnectURLs, url)
			}
			for url := range s.websocket.connectURLsMap {
				s.info.WSConnectURLs = append(s.info.WSConnectURLs, url)
			}
		}
	*/
	// Send to all registered clients that support async INFO protocols.
	s.sendAsyncInfoToClients(true, true)
	// We now clear the info.LameDuckMode flag so that if there are
	// cluster updates and we send the INFO, we don't have the boolean
	// set which would cause multiple LDM notifications to clients.
	s.info.LameDuckMode = false
}

// If given error is a net.Error and is temporary, sleeps for the given
// delay and double it, but cap it to ACCEPT_MAX_SLEEP. The sleep is
// interrupted if the server is shutdown.
// An error message is displayed depending on the type of error.
// Returns the new (or unchanged) delay, or a negative value if the
// server has been or is being shutdown.
func (s *Server) acceptError(acceptName string, err error, tmpDelay time.Duration) time.Duration {
	if !s.isRunning() {
		return -1
	}
	if ne, ok := err.(net.Error); ok && ne.Temporary() {
		s.Errorf("Temporary %s Accept Error(%v), sleeping %dms", acceptName, ne, tmpDelay/time.Millisecond)
		select {
		case <-time.After(tmpDelay):
		case <-s.quitCh:
			return -1
		}
		tmpDelay *= 2
		if tmpDelay > ACCEPT_MAX_SLEEP {
			tmpDelay = ACCEPT_MAX_SLEEP
		}
	} else {
		s.Errorf("%s Accept error: %v", acceptName, err)
	}
	return tmpDelay
}

// Returns true for the first attempt and depending on the nature
// of the attempt (first connect or a reconnect), when the number
// of attempts is equal to the configured report attempts.
func (s *Server) shouldReportConnectErr(firstConnect bool, attempts int) bool {
	opts := s.getOpts()
	if firstConnect {
		if attempts == 1 || attempts%opts.ConnectErrorReports == 0 {
			return true
		}
		return false
	}
	if attempts == 1 || attempts%opts.ReconnectErrorReports == 0 {
		return true
	}
	return false
}
