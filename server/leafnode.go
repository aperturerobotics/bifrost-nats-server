// Copyright 2019-2020 The NATS Authors
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
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nuid"
)

// Warning when user configures leafnode TLS insecure
const leafnodeTLSInsecureWarning = "TLS certificate chain and hostname of solicited leafnodes will not be verified. DO NOT USE IN PRODUCTION!"

// When a loop is detected, delay the reconnect of solicited connection.
const leafNodeReconnectDelayAfterLoopDetected = 30 * time.Second

// When a server receives a message causing a permission violation, the
// connection is closed and it won't attempt to reconnect for that long.
const leafNodeReconnectAfterPermViolation = 30 * time.Second

// Prefix for loop detection subject
const leafNodeLoopDetectionSubjectPrefix = "$LDS."

type leaf struct {
	// We have any auth stuff here for solicited connections.
	remote *leafNodeCfg
	// isSpoke tells us what role we are playing.
	// Used when we receive a connection but otherside tells us they are a hub.
	isSpoke bool
	// remoteCluster is when we are a hub but the spoke leafnode is part of a cluster.
	remoteCluster string
	// Used to suppress sub and unsub interest. Same as routes but our audience
	// here is tied to this leaf node. This will hold all subscriptions except this
	// leaf nodes. This represents all the interest we want to send to the other side.
	smap map[string]int32
	// This map will contain all the subscriptions that have been added to the smap
	// during initLeafNodeSmapAndSendSubs. It is short lived and is there to avoid
	// race between processing of a sub where sub is added to account sublist but
	// updateSmap has not be called on that "thread", while in the LN readloop,
	// when processing CONNECT, initLeafNodeSmapAndSendSubs is invoked and add
	// this subscription to smap. When processing of the sub then calls updateSmap,
	// we would add it a second time in the smap causing later unsub to suppress the LS-.
	tsub  map[*subscription]struct{}
	tsubt *time.Timer
}

// Used for remote (solicited) leafnodes.
type leafNodeCfg struct {
	sync.RWMutex
	*RemoteLeafOpts
	tlsName   string
	username  string
	password  string
	perms     *Permissions
	connDelay time.Duration // Delay before a connect, could be used while detecting loop condition, etc..
}

// Check to see if this is a solicited leafnode. We do special processing for solicited.
func (c *client) isSolicitedLeafNode() bool {
	return c.kind == LEAF && c.leaf.remote != nil
}

// Returns true if this is a solicited leafnode and is not configured to be treated as a hub or a receiving
// connection leafnode where the otherside has declared itself to be the hub.
func (c *client) isSpokeLeafNode() bool {
	return c.kind == LEAF && c.leaf.isSpoke
}

func (c *client) isHubLeafNode() bool {
	return c.kind == LEAF && !c.leaf.isSpoke
}

// This will spin up go routines to solicit the remote leaf node connections.
func (s *Server) solicitLeafNodeRemotes(remotes []*RemoteLeafOpts) {
	for _, r := range remotes {
		remote := newLeafNodeCfg(r)
		s.startGoRoutine(func() { s.connectToRemoteLeafNode(remote, true) })
	}
}

func (s *Server) remoteLeafNodeStillValid(remote *leafNodeCfg) bool {
	for _, ri := range s.getOpts().LeafNode.Remotes {
		if ri.Name == remote.Name {
			return true
		}
	}
	return false
}

// Ensure that leafnode is properly configured.
func validateLeafNode(o *Options) error {
	if o.Gateway.Name == "" {
		return nil
	}
	// If we are here we have both leaf nodes and gateways defined, make sure there
	// is a system account defined.
	if o.SystemAccount == "" {
		return fmt.Errorf("leaf nodes and gateways (both being defined) require a system account to also be configured")
	}
	return nil
}

func (s *Server) reConnectToRemoteLeafNode(remote *leafNodeCfg) {
	delay := s.getOpts().LeafNode.ReconnectInterval
	select {
	case <-time.After(delay):
	case <-s.quitCh:
		s.grWG.Done()
		return
	}
	s.connectToRemoteLeafNode(remote, false)
}

// Creates a leafNodeCfg object that wraps the RemoteLeafOpts.
func newLeafNodeCfg(remote *RemoteLeafOpts) *leafNodeCfg {
	cfg := &leafNodeCfg{
		RemoteLeafOpts: remote,
	}
	if len(remote.DenyExports) > 0 || len(remote.DenyImports) > 0 {
		perms := &Permissions{}
		if len(remote.DenyExports) > 0 {
			perms.Publish = &SubjectPermission{Deny: remote.DenyExports}
		}
		if len(remote.DenyImports) > 0 {
			perms.Subscribe = &SubjectPermission{Deny: remote.DenyImports}
		}
		cfg.perms = perms
	}
	return cfg
}

// Returns how long the server should wait before attempting
// to solicit a remote leafnode connection.
func (cfg *leafNodeCfg) getConnectDelay() time.Duration {
	cfg.RLock()
	delay := cfg.connDelay
	cfg.RUnlock()
	return delay
}

// Sets the connect delay.
func (cfg *leafNodeCfg) setConnectDelay(delay time.Duration) {
	cfg.Lock()
	cfg.connDelay = delay
	cfg.Unlock()
}

func (s *Server) connectToRemoteLeafNode(remote *leafNodeCfg, firstConnect bool) {
	defer s.grWG.Done()

	if remote == nil || len(remote.Name) == 0 {
		s.Debugf("Empty remote leafnode definition or definition name, nothing to connect")
		return
	}

	opts := s.getOpts()
	reconnectDelay := opts.LeafNode.ReconnectInterval

	if connDelay := remote.getConnectDelay(); connDelay > 0 {
		select {
		case <-time.After(connDelay):
		case <-s.quitCh:
			return
		}
		remote.setConnectDelay(0)
	}

	var conn net.Conn

	const connErrFmt = "Error trying to connect as leafnode to remote server %q (attempt %v): %v"

	attempts := 0
	for s.isRunning() && s.remoteLeafNodeStillValid(remote) {
		err := errors.New("TODO EstablishLink connectToRemoteLeafNode nats")
		if err != nil {
			attempts++
			if s.shouldReportConnectErr(firstConnect, attempts) {
				s.Errorf(connErrFmt, remote.Name, attempts, err)
			} else {
				s.Debugf(connErrFmt, remote.Name, attempts, err)
			}
			select {
			case <-s.quitCh:
				return
			case <-time.After(reconnectDelay):
				continue
			}
		}
		if !s.remoteLeafNodeStillValid(remote) {
			conn.Close()
			return
		}

		// We have a connection here to a remote server.
		// Go ahead and create our leaf node and return.
		s.createLeafNode(conn, remote)

		// We will put this in the normal log if first connect, does not force -DV mode to know
		// that the connect worked.
		// if firstConnect {
		s.Noticef("Connected leafnode to %q", remote.Name)
		// }
		return
	}
}

// Save off the username/password for when we connect using a bare URL
// that we get from the INFO protocol.
func (cfg *leafNodeCfg) saveUserPassword(u *url.URL) {
	if cfg.username == _EMPTY_ && u.User != nil {
		cfg.username = u.User.Username()
		cfg.password, _ = u.User.Password()
	}
}

// This starts the leafnode accept loop in a go routine, unless it
// is detected that the server has already been shutdown.
func (s *Server) startLeafNodeAcceptLoop() {
	// Snapshot server options.
	// opts := s.getOpts()

	/*
		port := opts.LeafNode.Port
		if port == -1 {
			port = 0
		}
	*/

	s.mu.Lock()
	if s.shutdown {
		s.mu.Unlock()
		return
	}

	s.Noticef("Listening for leafnode connections on internal mux")

	info := Info{
		ID:         s.info.ID,
		Version:    s.info.Version,
		GitCommit:  gitCommit,
		GoVersion:  runtime.Version(),
		MaxPayload: s.info.MaxPayload, // TODO(dlc) - Allow override?
		Headers:    s.supportsHeaders(),
		Proto:      1, // Fixed for now.
	}

	s.leafNodeInfo = info
	// s.leafURLsMap[s.leafNodeInfo.IP]++
	s.generateLeafNodeInfoJSON()

	// s.leafNodeListener = l
	// go s.acceptConnections(l, "Leafnode", func(conn net.Conn) { s.createLeafNode(conn, nil) }, nil)
	s.mu.Unlock()
}

// RegEx to match a creds file with user JWT and Seed.
var credsRe = regexp.MustCompile(`\s*(?:(?:[-]{3,}[^\n]*[-]{3,}\n)(.+)(?:\n\s*[-]{3,}[^\n]*[-]{3,}\n))`)

// Lock should be held entering here.
func (c *client) sendLeafConnect(clusterName string) error {
	// We support basic user/pass and operator based user JWT with signatures.
	cinfo := leafConnectInfo{
		// TLS:     tlsRequired,
		Name:    c.srv.info.ID,
		Hub:     c.leaf.remote.Hub,
		Cluster: clusterName,
	}

	// Check for credentials first, that will take precedence..
	if creds := c.leaf.remote.Credentials; creds != "" {
		c.Debugf("Authenticating with credentials file %q", c.leaf.remote.Credentials)
		contents, err := ioutil.ReadFile(creds)
		if err != nil {
			c.Errorf("%v", err)
			return err
		}
		defer wipeSlice(contents)
		items := credsRe.FindAllSubmatch(contents, -1)
		if len(items) < 2 {
			c.Errorf("Credentials file malformed")
			return err
		}
		// First result should be the user JWT.
		// We copy here so that the file containing the seed will be wiped appropriately.
		raw := items[0][1]
		tmp := make([]byte, len(raw))
		copy(tmp, raw)
		// Seed is second item.
		kp, err := nkeys.FromSeed(items[1][1])
		if err != nil {
			c.Errorf("Credentials file has malformed seed")
			return err
		}
		// Wipe our key on exit.
		defer kp.Wipe()

		sigraw, _ := kp.Sign(c.nonce)
		sig := base64.RawURLEncoding.EncodeToString(sigraw)
		cinfo.JWT = string(tmp)
		cinfo.Sig = sig
	} else if c.leaf.remote.username != _EMPTY_ {
		cinfo.User = c.leaf.remote.username
		cinfo.Pass = c.leaf.remote.password
	}
	b, err := json.Marshal(cinfo)
	if err != nil {
		c.Errorf("Error marshaling CONNECT to route: %v\n", err)
		return err
	}
	// Although this call is made before the writeLoop is created,
	// we don't really need to send in place. The protocol will be
	// sent out by the writeLoop.
	c.enqueueProto([]byte(fmt.Sprintf(ConProto, b)))
	return nil
}

// Makes a deep copy of the LeafNode Info structure.
// The server lock is held on entry.
func (s *Server) copyLeafNodeInfo() *Info {
	clone := s.leafNodeInfo
	return &clone
}

// Server lock is held on entry
func (s *Server) generateLeafNodeInfoJSON() {
	b, _ := json.Marshal(s.leafNodeInfo)
	pcs := [][]byte{[]byte("INFO"), b, []byte(CR_LF)}
	s.leafNodeInfoJSON = bytes.Join(pcs, []byte(" "))
}

// Sends an async INFO protocol so that the connected servers can update
// their list of LeafNode urls.
func (s *Server) sendAsyncLeafNodeInfo() {
	for _, c := range s.leafs {
		c.mu.Lock()
		c.enqueueProto(s.leafNodeInfoJSON)
		c.mu.Unlock()
	}
}

// Called when an inbound leafnode connection is accepted or we create one for a solicited leafnode.
func (s *Server) createLeafNode(conn net.Conn, remote *leafNodeCfg) *client {
	// Snapshot server options.
	opts := s.getOpts()

	maxPay := int32(opts.MaxPayload)
	maxSubs := int32(opts.MaxSubs)
	// For system, maxSubs of 0 means unlimited, so re-adjust here.
	if maxSubs == 0 {
		maxSubs = -1
	}
	now := time.Now()

	c := &client{srv: s, nc: conn, kind: LEAF, opts: defaultOpts, mpay: maxPay, msubs: maxSubs, start: now, last: now}
	// Do not update the smap here, we need to do it in initLeafNodeSmapAndSendSubs
	c.leaf = &leaf{}

	// Determines if we are soliciting the connection or not.
	var solicited bool
	var sendSysConnectEvent bool
	var acc *Account

	c.mu.Lock()
	c.initClient()
	if remote != nil {
		solicited = true
		// Users can bind to any local account, if its empty
		// we will assume the $G account.
		if remote.LocalAccount == "" {
			remote.LocalAccount = globalAccountName
		}
		c.leaf.remote = remote
		c.setPermissions(remote.perms)
		if c.leaf.remote.Hub {
			sendSysConnectEvent = true
		} else {
			c.leaf.isSpoke = true
		}
		c.mu.Unlock()
		// TODO: Decide what should be the optimal behavior here.
		// For now, if lookup fails, we will constantly try
		// to recreate this LN connection.
		var err error
		acc, err = s.LookupAccount(remote.LocalAccount)
		if err != nil {
			c.Errorf("No local account %q for leafnode: %v", remote.LocalAccount, err)
			c.closeConnection(MissingAccount)
			return nil
		}
		c.mu.Lock()
		c.acc = acc
	} else {
		c.flags.set(expectConnect)
	}
	c.mu.Unlock()

	var nonce [nonceLen]byte

	// Grab server variables
	s.mu.Lock()
	info := s.copyLeafNodeInfo()
	if !solicited {
		s.generateNonce(nonce[:])
	}
	clusterName := s.info.Cluster
	s.mu.Unlock()

	// Grab lock
	c.mu.Lock()

	if solicited {
		// We need to wait here for the info, but not for too long.
		c.nc.SetReadDeadline(time.Now().Add(DEFAULT_LEAFNODE_INFO_WAIT))
		br := bufio.NewReaderSize(c.nc, MAX_CONTROL_LINE_SIZE)
		info, err := br.ReadString('\n')
		if err != nil {
			c.mu.Unlock()
			if err == io.EOF {
				c.closeConnection(ClientClosed)
			} else {
				c.closeConnection(ReadError)
			}
			return nil
		}
		c.nc.SetReadDeadline(time.Time{})

		c.mu.Unlock()
		// Handle only connection to wrong port here, others will be handled below.
		if err := c.parse([]byte(info)); err == ErrConnectedToWrongPort {
			c.Errorf(err.Error())
			c.closeConnection(WrongPort)
			return nil
		}
		c.mu.Lock()

		if !c.flags.isSet(infoReceived) {
			c.mu.Unlock()
			c.Errorf("Did not get the remote leafnode's INFO, timed-out")
			c.closeConnection(ReadError)
			return nil
		}

		if err := c.sendLeafConnect(clusterName); err != nil {
			c.mu.Unlock()
			c.closeConnection(ProtocolViolation)
			return nil
		}
		c.Debugf("Remote leafnode connect msg sent")

	} else {
		// Send our info to the other side.
		// Remember the nonce we sent here for signatures, etc.
		c.nonce = make([]byte, nonceLen)
		copy(c.nonce, nonce[:])
		info.Nonce = string(c.nonce)
		info.CID = c.cid
		b, _ := json.Marshal(info)
		pcs := [][]byte{[]byte("INFO"), b, []byte(CR_LF)}
		// We have to send from this go routine because we may
		// have to block for TLS handshake before we start our
		// writeLoop go routine. The other side needs to receive
		// this before it can initiate the TLS handshake..
		c.sendProtoNow(bytes.Join(pcs, []byte(" ")))
	}

	// Keep track in case server is shutdown before we can successfully register.
	if !s.addToTempClients(c.cid, c) {
		c.mu.Unlock()
		c.setNoReconnect()
		c.closeConnection(ServerShutdown)
		return nil
	}

	// Spin up the read loop.
	s.startGoRoutine(func() { c.readLoop(nil) })

	// Spin up the write loop.
	s.startGoRoutine(func() { c.writeLoop() })

	c.mu.Unlock()

	c.Debugf("Leafnode connection created")

	// Update server's accounting here if we solicited.
	// Also send our local subs.
	if solicited {
		// Make sure we register with the account here.
		c.registerWithAccount(acc)
		s.addLeafNodeConnection(c)
		s.initLeafNodeSmapAndSendSubs(c)
		if sendSysConnectEvent {
			s.sendLeafNodeConnect(acc)
		}

		// The above functions are not atomically under the client
		// lock doing those operations. It is possible - since we
		// have started the read/write loops - that the connection
		// is closed before or in between. This would leave the
		// closed LN connection possible registered with the account
		// and/or the server's leafs map. So check if connection
		// is closed, and if so, manually cleanup.
		c.mu.Lock()
		closed := c.isClosed()
		c.mu.Unlock()
		if closed {
			s.removeLeafNodeConnection(c)
			if prev := acc.removeClient(c); prev == 1 {
				s.decActiveAccounts()
			}
		}
	}

	return c
}

func (c *client) processLeafnodeInfo(info *Info) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.leaf == nil || c.isClosed() {
		return nil
	}

	// Mark that the INFO protocol has been received.
	// Note: For now, only the initial INFO has a nonce. We
	// will probably do auto key rotation at some point.
	if c.flags.setIfNotSet(infoReceived) {
		// Prevent connecting to non leafnode port. Need to do this only for
		// the first INFO, not for async INFO updates...
		//
		// Content of INFO sent by the server when accepting a tcp connection.
		// -------------------------------------------------------------------
		// Listen Port Of | CID | ClientConnectURLs | LeafNodeURLs | Gateway |
		// -------------------------------------------------------------------
		//      CLIENT    |  X* |        X**        |              |         |
		//      ROUTE     |     |        X**        |      X***    |         |
		//     GATEWAY    |     |                   |              |    X    |
		//     LEAFNODE   |  X  |                   |       X      |         |
		// -------------------------------------------------------------------
		// *   Not on older servers.
		// **  Not if "no advertise" is enabled.
		// *** Not if leafnode's "no advertise" is enabled.
		//
		// As seen from above, a solicited LeafNode connection should receive
		// from the remote server an INFO with CID and LeafNodeURLs. Anything
		// else should be considered an attempt to connect to a wrong port.
		if c.leaf.remote != nil && info.CID == 0 {
			return ErrConnectedToWrongPort
		}
		// Capture a nonce here.
		c.nonce = []byte(info.Nonce)
		supportsHeaders := c.srv.supportsHeaders()
		c.headers = supportsHeaders && info.Headers
	}

	// Check to see if we have permissions updates here.
	if info.Import != nil || info.Export != nil {
		perms := &Permissions{
			Publish:   info.Export,
			Subscribe: info.Import,
		}
		// Check if we have local deny clauses that we need to merge.
		if remote := c.leaf.remote; remote != nil {
			if len(remote.DenyExports) > 0 {
				perms.Publish.Deny = append(perms.Publish.Deny, remote.DenyExports...)
			}
			if len(remote.DenyImports) > 0 {
				perms.Subscribe.Deny = append(perms.Subscribe.Deny, remote.DenyImports...)
			}
		}
		c.setPermissions(perms)
	}

	return nil
}

func (s *Server) addLeafNodeConnection(c *client) {
	c.mu.Lock()
	cid := c.cid
	c.mu.Unlock()
	s.mu.Lock()
	s.leafs[cid] = c
	s.mu.Unlock()
	s.removeFromTempClients(cid)
}

func (s *Server) removeLeafNodeConnection(c *client) {
	c.mu.Lock()
	cid := c.cid
	if c.leaf != nil && c.leaf.tsubt != nil {
		c.leaf.tsubt.Stop()
		c.leaf.tsubt = nil
	}
	c.mu.Unlock()
	s.mu.Lock()
	delete(s.leafs, cid)
	s.mu.Unlock()
	s.removeFromTempClients(cid)
}

type leafConnectInfo struct {
	JWT     string `json:"jwt,omitempty"`
	Sig     string `json:"sig,omitempty"`
	User    string `json:"user,omitempty"`
	Pass    string `json:"pass,omitempty"`
	TLS     bool   `json:"tls_required"`
	Comp    bool   `json:"compression,omitempty"`
	Name    string `json:"name,omitempty"`
	Hub     bool   `json:"is_hub,omitempty"`
	Cluster string `json:"cluster,omitempty"`

	// Just used to detect wrong connection attempts.
	Gateway string `json:"gateway,omitempty"`
}

// processLeafNodeConnect will process the inbound connect args.
// Once we are here we are bound to an account, so can send any interest that
// we would have to the other side.
func (c *client) processLeafNodeConnect(s *Server, arg []byte, lang string) error {
	// Way to detect clients that incorrectly connect to the route listen
	// port. Client provided "lang" in the CONNECT protocol while LEAFNODEs don't.
	if lang != "" {
		c.sendErrAndErr(ErrClientConnectedToLeafNodePort.Error())
		c.closeConnection(WrongPort)
		return ErrClientConnectedToLeafNodePort
	}

	// Unmarshal as a leaf node connect protocol
	proto := &leafConnectInfo{}
	if err := json.Unmarshal(arg, proto); err != nil {
		return err
	}

	// Reject if this has Gateway which means that it would be from a gateway
	// connection that incorrectly connects to the leafnode port.
	if proto.Gateway != "" {
		errTxt := fmt.Sprintf("Rejecting connection from gateway %q on the leafnode port", proto.Gateway)
		c.Errorf(errTxt)
		c.sendErr(errTxt)
		c.closeConnection(WrongGateway)
		return ErrWrongGateway
	}

	// Leaf Nodes do not do echo or verbose or pedantic.
	c.opts.Verbose = false
	c.opts.Echo = false
	c.opts.Pedantic = false

	// If the other side has declared itself a hub, so we will take on the spoke role.
	if proto.Hub {
		c.leaf.isSpoke = true
	}

	// The soliciting side is part of a cluster.
	if proto.Cluster != "" {
		c.leaf.remoteCluster = proto.Cluster
	}

	// If we have permissions bound to this leafnode we need to send then back to the
	// origin server for local enforcement.
	s.sendPermsInfo(c)

	// Create and initialize the smap since we know our bound account now.
	// This will send all registered subs too.
	s.initLeafNodeSmapAndSendSubs(c)

	// Add in the leafnode here since we passed through auth at this point.
	s.addLeafNodeConnection(c)

	// Announce the account connect event for a leaf node.
	// This will no-op as needed.
	s.sendLeafNodeConnect(c.acc)

	return nil
}

// Returns the remote cluster name. This is set only once so does not require a lock.
func (c *client) remoteCluster() string {
	if c.leaf == nil {
		return ""
	}
	return c.leaf.remoteCluster
}

// Sends back an info block to the soliciting leafnode to let it know about
// its permission settings for local enforcement.
func (s *Server) sendPermsInfo(c *client) {
	if c.perms == nil {
		return
	}
	// Copy
	info := s.copyLeafNodeInfo()
	c.mu.Lock()
	info.CID = c.cid
	info.Import = c.opts.Import
	info.Export = c.opts.Export
	b, _ := json.Marshal(info)
	pcs := [][]byte{[]byte("INFO"), b, []byte(CR_LF)}
	c.enqueueProto(bytes.Join(pcs, []byte(" ")))
	c.mu.Unlock()
}

// Snapshot the current subscriptions from the sublist into our smap which
// we will keep updated from now on.
// Also send the registered subscriptions.
func (s *Server) initLeafNodeSmapAndSendSubs(c *client) {
	acc := c.acc
	if acc == nil {
		c.Debugf("Leafnode does not have an account bound")
		return
	}
	// Collect all account subs here.
	_subs := [32]*subscription{}
	subs := _subs[:0]
	ims := []string{}
	acc.mu.Lock()
	accName := acc.Name
	// If we are solicited we only send interest for local clients.
	if c.isSpokeLeafNode() {
		acc.sl.localSubs(&subs)
	} else {
		acc.sl.All(&subs)
	}

	// Check if we have an existing service import reply.
	siReply := acc.siReply

	// Since leaf nodes only send on interest, if the bound
	// account has import services we need to send those over.
	for isubj := range acc.imports.services {
		ims = append(ims, isubj)
	}
	// Create a unique subject that will be used for loop detection.
	lds := acc.lds
	if lds == _EMPTY_ {
		lds = leafNodeLoopDetectionSubjectPrefix + nuid.Next()
		acc.lds = lds
	}
	acc.mu.Unlock()

	// Now check for gateway interest. Leafnodes will put this into
	// the proper mode to propagate, but they are not held in the account.
	gwsa := [16]*client{}
	gws := gwsa[:0]
	s.getOutboundGatewayConnections(&gws)
	for _, cgw := range gws {
		cgw.mu.Lock()
		gw := cgw.gw
		cgw.mu.Unlock()
		if gw != nil {
			if ei, _ := gw.outsim.Load(accName); ei != nil {
				if e := ei.(*outsie); e != nil && e.sl != nil {
					e.sl.All(&subs)
				}
			}
		}
	}

	applyGlobalRouting := s.gateway.enabled
	if c.isSpokeLeafNode() {
		// Add a fake subscription for this solicited leafnode connection
		// so that we can send back directly for mapped GW replies.
		c.srv.gwLeafSubs.Insert(&subscription{client: c, subject: []byte(gwReplyPrefix + ">")})
	}

	// Now walk the results and add them to our smap
	c.mu.Lock()
	c.leaf.smap = make(map[string]int32)
	for _, sub := range subs {
		// We ignore ourselves here.
		if c != sub.client {
			c.leaf.smap[keyFromSub(sub)]++
			if c.leaf.tsub == nil {
				c.leaf.tsub = make(map[*subscription]struct{})
			}
			c.leaf.tsub[sub] = struct{}{}
		}
	}
	// FIXME(dlc) - We need to update appropriately on an account claims update.
	for _, isubj := range ims {
		c.leaf.smap[isubj]++
	}
	// If we have gateways enabled we need to make sure the other side sends us responses
	// that have been augmented from the original subscription.
	// TODO(dlc) - Should we lock this down more?
	if applyGlobalRouting {
		c.leaf.smap[oldGWReplyPrefix+"*.>"]++
		c.leaf.smap[gwReplyPrefix+">"]++
	}
	// Detect loop by subscribing to a specific subject and checking
	// if this is coming back to us.
	c.leaf.smap[lds]++

	// Check if we need to add an existing siReply to our map.
	// This will be a prefix so add on the wildcard.
	if siReply != nil {
		wcsub := append(siReply, '>')
		c.leaf.smap[string(wcsub)]++
	}
	// Queue all protocols. There is no max pending limit for LN connection,
	// so we don't need chunking. The writes will happen from the writeLoop.
	var b bytes.Buffer
	for key, n := range c.leaf.smap {
		c.writeLeafSub(&b, key, n)
	}
	if b.Len() > 0 {
		c.enqueueProto(b.Bytes())
	}
	if c.leaf.tsub != nil {
		// Clear the tsub map after 5 seconds.
		c.leaf.tsubt = time.AfterFunc(5*time.Second, func() {
			c.mu.Lock()
			if c.leaf != nil {
				c.leaf.tsub = nil
				c.leaf.tsubt = nil
			}
			c.mu.Unlock()
		})
	}
	c.mu.Unlock()
}

// updateInterestForAccountOnGateway called from gateway code when processing RS+ and RS-.
func (s *Server) updateInterestForAccountOnGateway(accName string, sub *subscription, delta int32) {
	acc, err := s.LookupAccount(accName)
	if acc == nil || err != nil {
		s.Debugf("No or bad account for %q, failed to update interest from gateway", accName)
		return
	}
	s.updateLeafNodes(acc, sub, delta)
}

// updateLeafNodes will make sure to update the smap for the subscription. Will
// also forward to all leaf nodes as needed.
func (s *Server) updateLeafNodes(acc *Account, sub *subscription, delta int32) {
	if acc == nil || sub == nil {
		return
	}

	_l := [32]*client{}
	leafs := _l[:0]

	// Grab all leaf nodes. Ignore a leafnode if sub's client is a leafnode and matches.
	acc.mu.RLock()
	for _, ln := range acc.lleafs {
		if ln != sub.client {
			leafs = append(leafs, ln)
		}
	}
	acc.mu.RUnlock()

	for _, ln := range leafs {
		// Check to make sure this sub does not have an origin cluster than matches the leafnode.
		if sub.origin != nil && string(sub.origin) == ln.remoteCluster() {
			continue
		}
		ln.updateSmap(sub, delta)
	}
}

// This will make an update to our internal smap and determine if we should send out
// an interest update to the remote side.
func (c *client) updateSmap(sub *subscription, delta int32) {
	key := keyFromSub(sub)

	c.mu.Lock()
	if c.leaf.smap == nil {
		c.mu.Unlock()
		return
	}

	// If we are solicited make sure this is a local client or a non-solicited leaf node
	skind := sub.client.kind
	updateClient := skind == CLIENT || skind == SYSTEM || skind == JETSTREAM || skind == ACCOUNT
	if c.isSpokeLeafNode() && !(updateClient || (skind == LEAF && !sub.client.isSpokeLeafNode())) {
		c.mu.Unlock()
		return
	}

	// For additions, check if that sub has just been processed during initLeafNodeSmapAndSendSubs
	if delta > 0 && c.leaf.tsub != nil {
		if _, present := c.leaf.tsub[sub]; present {
			delete(c.leaf.tsub, sub)
			if len(c.leaf.tsub) == 0 {
				c.leaf.tsub = nil
				c.leaf.tsubt.Stop()
				c.leaf.tsubt = nil
			}
			c.mu.Unlock()
			return
		}
	}

	n := c.leaf.smap[key]
	// We will update if its a queue, if count is zero (or negative), or we were 0 and are N > 0.
	update := sub.queue != nil || n == 0 || n+delta <= 0
	n += delta
	if n > 0 {
		c.leaf.smap[key] = n
	} else {
		delete(c.leaf.smap, key)
	}
	if update {
		c.sendLeafNodeSubUpdate(key, n)
	}
	c.mu.Unlock()
}

// Send the subscription interest change to the other side.
// Lock should be held.
func (c *client) sendLeafNodeSubUpdate(key string, n int32) {
	// If we are a spoke, we need to check if we are allowed to send this subscription over to the hub.
	if c.isSpokeLeafNode() {
		checkPerms := true
		if len(key) > 0 && (key[0] == '$' || key[0] == '_') {
			if strings.HasPrefix(key, leafNodeLoopDetectionSubjectPrefix) ||
				strings.HasPrefix(key, oldGWReplyPrefix) ||
				strings.HasPrefix(key, gwReplyPrefix) {
				checkPerms = false
			}
		}
		if checkPerms && !c.canSubscribe(key) {
			return
		}
	}
	// If we are here we can send over to the other side.
	_b := [64]byte{}
	b := bytes.NewBuffer(_b[:0])
	c.writeLeafSub(b, key, n)
	c.enqueueProto(b.Bytes())
}

// Helper function to build the key.
func keyFromSub(sub *subscription) string {
	var _rkey [1024]byte
	var key []byte

	if sub.queue != nil {
		// Just make the key subject spc group, e.g. 'foo bar'
		key = _rkey[:0]
		key = append(key, sub.subject...)
		key = append(key, byte(' '))
		key = append(key, sub.queue...)
	} else {
		key = sub.subject
	}
	return string(key)
}

// Lock should be held.
func (c *client) writeLeafSub(w *bytes.Buffer, key string, n int32) {
	if key == "" {
		return
	}
	if n > 0 {
		w.WriteString("LS+ " + key)
		// Check for queue semantics, if found write n.
		if strings.Contains(key, " ") {
			w.WriteString(" ")
			var b [12]byte
			var i = len(b)
			for l := n; l > 0; l /= 10 {
				i--
				b[i] = digits[l%10]
			}
			w.Write(b[i:])
			if c.trace {
				arg := fmt.Sprintf("%s %d", key, n)
				c.traceOutOp("LS+", []byte(arg))
			}
		} else if c.trace {
			c.traceOutOp("LS+", []byte(key))
		}
	} else {
		w.WriteString("LS- " + key)
		if c.trace {
			c.traceOutOp("LS-", []byte(key))
		}
	}
	w.WriteString(CR_LF)
}

// processLeafSub will process an inbound sub request for the remote leaf node.
func (c *client) processLeafSub(argo []byte) (err error) {
	// Indicate activity.
	c.in.subs++

	srv := c.srv
	if srv == nil {
		return nil
	}

	// Copy so we do not reference a potentially large buffer
	arg := make([]byte, len(argo))
	copy(arg, argo)

	args := splitArg(arg)
	sub := &subscription{client: c}

	switch len(args) {
	case 1:
		sub.queue = nil
	case 3:
		sub.queue = args[1]
		sub.qw = int32(parseSize(args[2]))
	default:
		return fmt.Errorf("processLeafSub Parse Error: '%s'", arg)
	}
	sub.subject = args[0]

	c.mu.Lock()
	if c.isClosed() {
		c.mu.Unlock()
		return nil
	}

	acc := c.acc
	// Check if we have a loop.
	ldsPrefix := bytes.HasPrefix(sub.subject, []byte(leafNodeLoopDetectionSubjectPrefix))
	if ldsPrefix && string(sub.subject) == acc.getLDSubject() {
		c.mu.Unlock()
		c.handleLeafNodeLoop(true)
		return nil
	}

	// Check permissions if applicable. (but exclude the $LDS, $GR and _GR_)
	checkPerms := true
	if sub.subject[0] == '$' || sub.subject[0] == '_' {
		if ldsPrefix ||
			bytes.HasPrefix(sub.subject, []byte(oldGWReplyPrefix)) ||
			bytes.HasPrefix(sub.subject, []byte(gwReplyPrefix)) {
			checkPerms = false
		}
	}
	if checkPerms && c.isHubLeafNode() && !c.canSubscribe(string(sub.subject)) {
		c.mu.Unlock()
		c.leafSubPermViolation(sub.subject)
		return nil
	}

	// Check if we have a maximum on the number of subscriptions.
	if c.subsAtLimit() {
		c.mu.Unlock()
		c.maxSubsExceeded()
		return nil
	}

	// If we have an origin cluster associated mark that in the sub.
	if rc := c.remoteCluster(); rc != _EMPTY_ {
		sub.origin = []byte(rc)
	}

	// Like Routes, we store local subs by account and subject and optionally queue name.
	// If we have a queue it will have a trailing weight which we do not want.
	if sub.queue != nil {
		sub.sid = arg[:len(arg)-len(args[2])-1]
	} else {
		sub.sid = arg
	}
	key := string(sub.sid)
	osub := c.subs[key]
	updateGWs := false
	if osub == nil {
		c.subs[key] = sub
		// Now place into the account sl.
		if err := acc.sl.Insert(sub); err != nil {
			delete(c.subs, key)
			c.mu.Unlock()
			c.Errorf("Could not insert subscription: %v", err)
			c.sendErr("Invalid Subscription")
			return nil
		}
		updateGWs = srv.gateway.enabled
	} else if sub.queue != nil {
		// For a queue we need to update the weight.
		atomic.StoreInt32(&osub.qw, sub.qw)
		acc.sl.UpdateRemoteQSub(osub)
	}
	spoke := c.isSpokeLeafNode()
	c.mu.Unlock()

	if err := c.addShadowSubscriptions(acc, sub); err != nil {
		c.Errorf(err.Error())
	}

	// If we are not solicited, treat leaf node subscriptions similar to a
	// client subscription, meaning we forward them to routes, gateways and
	// other leaf nodes as needed.
	if !spoke {
		// If we are routing add to the route map for the associated account.
		srv.updateRouteSubscriptionMap(acc, sub, 1)
		if updateGWs {
			srv.gatewayUpdateSubInterest(acc.Name, sub, 1)
		}
	}
	// Now check on leafnode updates for other leaf nodes. We understand solicited
	// and non-solicited state in this call so we will do the right thing.
	srv.updateLeafNodes(acc, sub, 1)

	return nil
}

// If the leafnode is a solicited, set the connect delay based on default
// or private option (for tests). Sends the error to the other side, log and
// close the connection.
func (c *client) handleLeafNodeLoop(sendErr bool) {
	accName, delay := c.setLeafConnectDelayIfSoliciting(leafNodeReconnectDelayAfterLoopDetected)
	errTxt := fmt.Sprintf("Loop detected for leafnode account=%q. Delaying attempt to reconnect for %v", accName, delay)
	if sendErr {
		c.sendErr(errTxt)
	}
	c.Errorf(errTxt)
	// If we are here with "sendErr" false, it means that this is the server
	// that received the error. The other side will have closed the connection,
	// but does not hurt to close here too.
	c.closeConnection(ProtocolViolation)
}

// processLeafUnsub will process an inbound unsub request for the remote leaf node.
func (c *client) processLeafUnsub(arg []byte) error {
	// Indicate any activity, so pub and sub or unsubs.
	c.in.subs++

	acc := c.acc
	srv := c.srv

	c.mu.Lock()
	if c.isClosed() {
		c.mu.Unlock()
		return nil
	}

	updateGWs := false
	// We store local subs by account and subject and optionally queue name.
	// LS- will have the arg exactly as the key.
	sub, ok := c.subs[string(arg)]
	c.mu.Unlock()

	if ok {
		c.unsubscribe(acc, sub, true, true)
		updateGWs = srv.gateway.enabled
	}

	// If we are routing subtract from the route map for the associated account.
	srv.updateRouteSubscriptionMap(acc, sub, -1)
	// Gateways
	if updateGWs {
		srv.gatewayUpdateSubInterest(acc.Name, sub, -1)
	}
	// Now check on leafnode updates for other leaf nodes.
	srv.updateLeafNodes(acc, sub, -1)
	return nil
}

func (c *client) processLeafHeaderMsgArgs(arg []byte) error {
	// Unroll splitArgs to avoid runtime/heap issues
	a := [MAX_MSG_ARGS][]byte{}
	args := a[:0]
	start := -1
	for i, b := range arg {
		switch b {
		case ' ', '\t', '\r', '\n':
			if start >= 0 {
				args = append(args, arg[start:i])
				start = -1
			}
		default:
			if start < 0 {
				start = i
			}
		}
	}
	if start >= 0 {
		args = append(args, arg[start:])
	}

	c.pa.arg = arg
	switch len(args) {
	case 0, 1, 2:
		return fmt.Errorf("processLeafHeaderMsgArgs Parse Error: '%s'", args)
	case 3:
		c.pa.reply = nil
		c.pa.queues = nil
		c.pa.hdb = args[1]
		c.pa.hdr = parseSize(args[1])
		c.pa.szb = args[2]
		c.pa.size = parseSize(args[2])
	case 4:
		c.pa.reply = args[1]
		c.pa.queues = nil
		c.pa.hdb = args[2]
		c.pa.hdr = parseSize(args[2])
		c.pa.szb = args[3]
		c.pa.size = parseSize(args[3])
	default:
		// args[1] is our reply indicator. Should be + or | normally.
		if len(args[1]) != 1 {
			return fmt.Errorf("processLeafHeaderMsgArgs Bad or Missing Reply Indicator: '%s'", args[1])
		}
		switch args[1][0] {
		case '+':
			c.pa.reply = args[2]
		case '|':
			c.pa.reply = nil
		default:
			return fmt.Errorf("processLeafHeaderMsgArgs Bad or Missing Reply Indicator: '%s'", args[1])
		}
		// Grab header size.
		c.pa.hdb = args[len(args)-2]
		c.pa.hdr = parseSize(c.pa.hdb)

		// Grab size.
		c.pa.szb = args[len(args)-1]
		c.pa.size = parseSize(c.pa.szb)

		// Grab queue names.
		if c.pa.reply != nil {
			c.pa.queues = args[3 : len(args)-2]
		} else {
			c.pa.queues = args[2 : len(args)-2]
		}
	}
	if c.pa.hdr < 0 {
		return fmt.Errorf("processLeafHeaderMsgArgs Bad or Missing Header Size: '%s'", arg)
	}
	if c.pa.size < 0 {
		return fmt.Errorf("processLeafHeaderMsgArgs Bad or Missing Size: '%s'", args)
	}
	if c.pa.hdr > c.pa.size {
		return fmt.Errorf("processLeafHeaderMsgArgs Header Size larger then TotalSize: '%s'", arg)
	}

	// Common ones processed after check for arg length
	c.pa.subject = args[0]

	return nil
}

func (c *client) processLeafMsgArgs(arg []byte) error {
	// Unroll splitArgs to avoid runtime/heap issues
	a := [MAX_MSG_ARGS][]byte{}
	args := a[:0]
	start := -1
	for i, b := range arg {
		switch b {
		case ' ', '\t', '\r', '\n':
			if start >= 0 {
				args = append(args, arg[start:i])
				start = -1
			}
		default:
			if start < 0 {
				start = i
			}
		}
	}
	if start >= 0 {
		args = append(args, arg[start:])
	}

	c.pa.arg = arg
	switch len(args) {
	case 0, 1:
		return fmt.Errorf("processLeafMsgArgs Parse Error: '%s'", args)
	case 2:
		c.pa.reply = nil
		c.pa.queues = nil
		c.pa.szb = args[1]
		c.pa.size = parseSize(args[1])
	case 3:
		c.pa.reply = args[1]
		c.pa.queues = nil
		c.pa.szb = args[2]
		c.pa.size = parseSize(args[2])
	default:
		// args[1] is our reply indicator. Should be + or | normally.
		if len(args[1]) != 1 {
			return fmt.Errorf("processLeafMsgArgs Bad or Missing Reply Indicator: '%s'", args[1])
		}
		switch args[1][0] {
		case '+':
			c.pa.reply = args[2]
		case '|':
			c.pa.reply = nil
		default:
			return fmt.Errorf("processLeafMsgArgs Bad or Missing Reply Indicator: '%s'", args[1])
		}
		// Grab size.
		c.pa.szb = args[len(args)-1]
		c.pa.size = parseSize(c.pa.szb)

		// Grab queue names.
		if c.pa.reply != nil {
			c.pa.queues = args[3 : len(args)-1]
		} else {
			c.pa.queues = args[2 : len(args)-1]
		}
	}
	if c.pa.size < 0 {
		return fmt.Errorf("processLeafMsgArgs Bad or Missing Size: '%s'", args)
	}

	// Common ones processed after check for arg length
	c.pa.subject = args[0]

	return nil
}

// processInboundLeafMsg is called to process an inbound msg from a leaf node.
func (c *client) processInboundLeafMsg(msg []byte) {
	// Update statistics
	// The msg includes the CR_LF, so pull back out for accounting.
	c.in.msgs++
	c.in.bytes += int32(len(msg) - LEN_CR_LF)

	// Check pub permissions
	if c.perms != nil && (c.perms.pub.allow != nil || c.perms.pub.deny != nil) && c.isHubLeafNode() && !c.pubAllowed(string(c.pa.subject)) {
		c.leafPubPermViolation(c.pa.subject)
		return
	}

	srv := c.srv
	acc := c.acc

	// Mostly under testing scenarios.
	if srv == nil || acc == nil {
		return
	}

	// Match the subscriptions. We will use our own L1 map if
	// it's still valid, avoiding contention on the shared sublist.
	var r *SublistResult
	var ok bool

	genid := atomic.LoadUint64(&c.acc.sl.genid)
	if genid == c.in.genid && c.in.results != nil {
		r, ok = c.in.results[string(c.pa.subject)]
	} else {
		// Reset our L1 completely.
		c.in.results = make(map[string]*SublistResult)
		c.in.genid = genid
	}

	// Go back to the sublist data structure.
	if !ok {
		r = c.acc.sl.Match(string(c.pa.subject))
		c.in.results[string(c.pa.subject)] = r
		// Prune the results cache. Keeps us from unbounded growth. Random delete.
		if len(c.in.results) > maxResultCacheSize {
			n := 0
			for subject := range c.in.results {
				delete(c.in.results, subject)
				if n++; n > pruneSize {
					break
				}
			}
		}
	}

	// Collect queue names if needed.
	var qnames [][]byte

	// Check for no interest, short circuit if so.
	// This is the fanout scale.
	if len(r.psubs)+len(r.qsubs) > 0 {
		flag := pmrNoFlag
		// If we have queue subs in this cluster, then if we run in gateway
		// mode and the remote gateways have queue subs, then we need to
		// collect the queue groups this message was sent to so that we
		// exclude them when sending to gateways.
		if len(r.qsubs) > 0 && c.srv.gateway.enabled &&
			atomic.LoadInt64(&c.srv.gateway.totalQSubs) > 0 {
			flag |= pmrCollectQueueNames
		}
		_, qnames = c.processMsgResults(acc, r, msg, nil, c.pa.subject, c.pa.reply, flag)
	}

	// Now deal with gateways
	if c.srv.gateway.enabled {
		c.sendMsgToGateways(acc, msg, c.pa.subject, c.pa.reply, qnames)
	}
}

// Handles a publish permission violation.
// See leafPermViolation() for details.
func (c *client) leafPubPermViolation(subj []byte) {
	c.leafPermViolation(true, subj)
}

// Handles a subscription permission violation.
// See leafPermViolation() for details.
func (c *client) leafSubPermViolation(subj []byte) {
	c.leafPermViolation(false, subj)
}

// Common function to process publish or subscribe leafnode permission violation.
// Sends the permission violation error to the remote, logs it and closes the connection.
// If this is from a server soliciting, the reconnection will be delayed.
func (c *client) leafPermViolation(pub bool, subj []byte) {
	if c.isSpokeLeafNode() {
		// For spokes these are no-ops since the hub server told us our permissions.
		// We just need to not send these over to the other side since we will get cutoff.
		return
	}
	// FIXME(dlc) ?
	c.setLeafConnectDelayIfSoliciting(leafNodeReconnectAfterPermViolation)
	var action string
	if pub {
		c.sendErr(fmt.Sprintf("Permissions Violation for Publish to %q", subj))
		action = "Publish"
	} else {
		c.sendErr(fmt.Sprintf("Permissions Violation for Subscription to %q", subj))
		action = "Subscription"
	}
	c.Errorf("%s Violation on %q - Check other side configuration", action, subj)
	// TODO: add a new close reason that is more appropriate?
	c.closeConnection(ProtocolViolation)
}

// Invoked from generic processErr() for LEAF connections.
func (c *client) leafProcessErr(errStr string) {
	// We will look for Loop detected error coming from the other side.
	// If we solicit, set the connect delay.
	if !strings.Contains(errStr, "Loop detected") {
		return
	}
	c.handleLeafNodeLoop(false)
}

// If this leaf connection solicits, sets the connect delay to the given value,
// or the one from the server option's LeafNode.connDelay if one is set (for tests).
// Returns the connection's account name and delay.
func (c *client) setLeafConnectDelayIfSoliciting(delay time.Duration) (string, time.Duration) {
	c.mu.Lock()
	if c.isSolicitedLeafNode() {
		c.leaf.remote.setConnectDelay(delay)
	}
	accName := c.acc.Name
	c.mu.Unlock()
	return accName, delay
}
