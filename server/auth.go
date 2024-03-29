// Copyright 2012-2019 The NATS Authors
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
	"encoding/base64"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"golang.org/x/crypto/bcrypt"
)

// Authentication is an interface for implementing authentication
type Authentication interface {
	// Check if a client is authorized to connect
	Check(c ClientAuthentication) bool
}

// ClientAuthentication is an interface for client authentication
type ClientAuthentication interface {
	// Get options associated with a client
	GetOpts() *clientOpts
	// RemoteAddress expose the connection information of the client
	RemoteAddress() net.Addr
}

// NkeyUser is for multiple nkey based users
type NkeyUser struct {
	Nkey        string       `json:"user"`
	Permissions *Permissions `json:"permissions,omitempty"`
	Account     *Account     `json:"account,omitempty"`
	SigningKey  string       `json:"signing_key,omitempty"`
}

// clone performs a deep copy of the NkeyUser struct, returning a new clone with
// all values copied.
func (n *NkeyUser) clone() *NkeyUser {
	if n == nil {
		return nil
	}
	clone := &NkeyUser{}
	*clone = *n
	clone.Permissions = n.Permissions.clone()
	return clone
}

// SubjectPermission is an individual allow and deny struct for publish
// and subscribe authorizations.
type SubjectPermission struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// ResponsePermission can be used to allow responses to any reply subject
// that is received on a valid subscription.
type ResponsePermission struct {
	MaxMsgs int           `json:"max"`
	Expires time.Duration `json:"ttl"`
}

// Permissions are the allowed subjects on a per
// publish or subscribe basis.
type Permissions struct {
	Publish   *SubjectPermission  `json:"publish"`
	Subscribe *SubjectPermission  `json:"subscribe"`
	Response  *ResponsePermission `json:"responses,omitempty"`
}

// RoutePermissions are similar to user permissions
// but describe what a server can import/export from and to
// another server.
type RoutePermissions struct {
	Import *SubjectPermission `json:"import"`
	Export *SubjectPermission `json:"export"`
}

// clone will clone an individual subject permission.
func (p *SubjectPermission) clone() *SubjectPermission {
	if p == nil {
		return nil
	}
	clone := &SubjectPermission{}
	if p.Allow != nil {
		clone.Allow = make([]string, len(p.Allow))
		copy(clone.Allow, p.Allow)
	}
	if p.Deny != nil {
		clone.Deny = make([]string, len(p.Deny))
		copy(clone.Deny, p.Deny)
	}
	return clone
}

// clone performs a deep copy of the Permissions struct, returning a new clone
// with all values copied.
func (p *Permissions) clone() *Permissions {
	if p == nil {
		return nil
	}
	clone := &Permissions{}
	if p.Publish != nil {
		clone.Publish = p.Publish.clone()
	}
	if p.Subscribe != nil {
		clone.Subscribe = p.Subscribe.clone()
	}
	if p.Response != nil {
		clone.Response = &ResponsePermission{
			MaxMsgs: p.Response.MaxMsgs,
			Expires: p.Response.Expires,
		}
	}
	return clone
}

// If Users or Nkeys options have definitions without an account defined,
// assign them to the default global account.
// Lock should be held.
func (s *Server) assignGlobalAccountToOrphanUsers(nkeys map[string]*NkeyUser) {
	for _, u := range nkeys {
		if u.Account == nil {
			u.Account = s.gacc
		}
	}
}

// If the given permissions has a ResponsePermission
// set, ensure that defaults are set (if values are 0)
// and that a Publish permission is set, and Allow
// is disabled if not explicitly set.
func validateResponsePermissions(p *Permissions) {
	if p == nil || p.Response == nil {
		return
	}
	if p.Publish == nil {
		p.Publish = &SubjectPermission{}
	}
	if p.Publish.Allow == nil {
		// We turn off the blanket allow statement.
		p.Publish.Allow = []string{}
	}
	// If there is a response permission, ensure
	// that if value is 0, we set the default value.
	if p.Response.MaxMsgs == 0 {
		p.Response.MaxMsgs = DEFAULT_ALLOW_RESPONSE_MAX_MSGS
	}
	if p.Response.Expires == 0 {
		p.Response.Expires = DEFAULT_ALLOW_RESPONSE_EXPIRATION
	}
}

// configureAuthorization will do any setup needed for authorization.
// Lock is assumed held.
func (s *Server) configureAuthorization() {
	opts := s.getOpts()
	if opts == nil {
		return
	}

	if opts.Nkeys != nil {
		s.nkeys = s.buildNkeysAndUsersFromOptions(opts.Nkeys)
	} else {
		s.nkeys = nil
	}
}

// Takes the given slices of NkeyUser and User options and build
// corresponding maps used by the server. The users are cloned
// so that server does not reference options.
// The global account is assigned to users that don't have an
// existing account.
// Server lock is held on entry.
func (s *Server) buildNkeysAndUsersFromOptions(nko []*NkeyUser) map[string]*NkeyUser {
	var nkeys map[string]*NkeyUser

	if nko != nil {
		nkeys = make(map[string]*NkeyUser, len(nko))
		for _, u := range nko {
			copy := u.clone()
			if u.Account != nil {
				if v, ok := s.accounts.Load(u.Account.Name); ok {
					copy.Account = v.(*Account)
				}
			}
			if copy.Permissions != nil {
				validateResponsePermissions(copy.Permissions)
			}
			nkeys[u.Nkey] = copy
		}
	}
	s.assignGlobalAccountToOrphanUsers(nkeys)
	return nkeys
}

// checkAuthentication will check based on client type and
// return boolean indicating if client is authorized.
func (s *Server) checkAuthentication(c *client) bool {
	switch c.kind {
	case CLIENT:
		return s.isClientAuthorized(c)
	case ROUTER:
		return s.isRouterAuthorized(c)
	case GATEWAY:
		return s.isGatewayAuthorized(c)
	case LEAF:
		return s.isLeafNodeAuthorized(c)
	default:
		return false
	}
}

// isClientAuthorized will check the client against the proper authorization method and data.
// This could be nkey, token, or username/password based.
func (s *Server) isClientAuthorized(c *client) bool {
	opts := s.getOpts()

	// Check custom auth first, then jwts, then nkeys, then single user/pass.
	if opts.CustomClientAuthentication != nil {
		return opts.CustomClientAuthentication.Check(c)
	}

	return s.processClientOrLeafAuthentication(c, opts)
}

func (s *Server) processClientOrLeafAuthentication(c *client, opts *Options) bool {
	var (
		nkey *NkeyUser
		juc  *jwt.UserClaims
		acc  *Account
		ok   bool
		err  error
		ao   bool // auth override
	)
	s.mu.Lock()
	var (
		nkusers map[string]*NkeyUser
	)
	if !ao {
		nkusers = s.nkeys
	}

	// Check if we have nkeys or users for client.
	hasNkeys := len(nkusers) > 0
	if hasNkeys && c.opts.Nkey != "" {
		nkey, ok = nkusers[c.opts.Nkey]
		if !ok {
			s.mu.Unlock()
			return false
		}
	}
	s.mu.Unlock()

	// If we have a jwt and a userClaim, make sure we have the Account, etc associated.
	// We need to look up the account. This will use an account resolver if one is present.
	if juc != nil {
		issuer := juc.Issuer
		if juc.IssuerAccount != "" {
			issuer = juc.IssuerAccount
		}
		if acc, err = s.LookupAccount(issuer); acc == nil {
			c.Debugf("Account JWT lookup error: %v", err)
			return false
		}
		if !s.isTrustedIssuer(acc.Issuer) {
			c.Debugf("Account JWT not signed by trusted operator")
			return false
		}
		if juc.IssuerAccount != "" && !acc.hasIssuer(juc.Issuer) {
			c.Debugf("User JWT issuer is not known")
			return false
		}
		if acc.IsExpired() {
			c.Debugf("Account JWT has expired")
			return false
		}
		// skip validation of nonce when presented with a bearer token
		// FIXME: if BearerToken is only for WSS, need check for server with that port enabled
		if !juc.BearerToken {
			// Verify the signature against the nonce.
			if c.opts.Sig == "" {
				c.Debugf("Signature missing")
				return false
			}
			sig, err := base64.RawURLEncoding.DecodeString(c.opts.Sig)
			if err != nil {
				// Allow fallback to normal base64.
				sig, err = base64.StdEncoding.DecodeString(c.opts.Sig)
				if err != nil {
					c.Debugf("Signature not valid base64")
					return false
				}
			}
			pub, err := nkeys.FromPublicKey(juc.Subject)
			if err != nil {
				c.Debugf("User nkey not valid: %v", err)
				return false
			}
			if err := pub.Verify(c.nonce, sig); err != nil {
				c.Debugf("Signature not verified")
				return false
			}
		}
		if acc.checkUserRevoked(juc.Subject) {
			c.Debugf("User authentication revoked")
			return false
		}
		allowNow, validFor := validateTimes(juc)
		if !allowNow {
			c.Errorf("Outside connect times")
			return false
		}
		_ = validFor

		nkey = buildInternalNkeyUser(juc, acc)
		if err := c.RegisterNkeyUser(nkey); err != nil {
			return false
		}
		// Hold onto the user's public key.
		c.pubKey = juc.Subject

		// Generate an event if we have a system account.
		s.accountConnectEvent(c)

		// Check if we need to set an auth timer if the user jwt expires.
		// TODO
		// c.setExpiration(juc.Claims(), validFor)
		return true
	}

	if nkey != nil {
		if c.opts.Sig == "" {
			c.Debugf("Signature missing")
			return false
		}
		sig, err := base64.RawURLEncoding.DecodeString(c.opts.Sig)
		if err != nil {
			// Allow fallback to normal base64.
			sig, err = base64.StdEncoding.DecodeString(c.opts.Sig)
			if err != nil {
				c.Debugf("Signature not valid base64")
				return false
			}
		}
		pub, err := nkeys.FromPublicKey(c.opts.Nkey)
		if err != nil {
			c.Debugf("User nkey not valid: %v", err)
			return false
		}
		if err := pub.Verify(c.nonce, sig); err != nil {
			c.Debugf("Signature not verified")
			return false
		}
		if err := c.RegisterNkeyUser(nkey); err != nil {
			return false
		}
		return true
	}

	if c.kind == LEAF {
		// There is no required username/password to connect and
		// there was no u/p in the CONNECT or none that matches the
		// know users. Register the leaf connection with global account
		// or the one specified in config (if provided).
		return s.registerLeafWithAccount(c, opts.LeafNode.Account)
	}

	return false
}

// checkRouterAuth checks optional router authorization which can be nil or username/password.
func (s *Server) isRouterAuthorized(c *client) bool {
	if s.opts.CustomRouterAuthentication != nil {
		return s.opts.CustomRouterAuthentication.Check(c)
	}

	return true
}

// isGatewayAuthorized checks optional gateway authorization which can be nil or username/password.
func (s *Server) isGatewayAuthorized(c *client) bool {
	return true
}

func (s *Server) registerLeafWithAccount(c *client, account string) bool {
	var err error
	acc := s.globalAccount()
	if account != _EMPTY_ {
		acc, err = s.lookupAccount(account)
		if err != nil {
			s.Errorf("authentication of user failed, unable to lookup account %q: %v",
				account, err)
			return false
		}
	}
	if err = c.registerWithAccount(acc); err != nil {
		return false
	}
	return true
}

// isLeafNodeAuthorized will check for auth for an inbound leaf node connection.
func (s *Server) isLeafNodeAuthorized(c *client) bool {
	opts := s.getOpts()

	isAuthorized := func(account string) bool {
		return s.registerLeafWithAccount(c, account)
	}

	// If leafnodes config has an authorization{} stanza, this takes precedence.
	// The user in CONNECT mutch match. We will bind to the account associated
	// with that user (from the leafnode's authorization{} config).
	if opts.LeafNode.Account != _EMPTY_ {
		return isAuthorized(opts.LeafNode.Account)
	}

	// We are here if we accept leafnode connections without any credentials.

	// Still, if the CONNECT has some user info, we will bind to the
	// user's account or to the specified default account (if provided)
	// or to the global account.
	return s.processClientOrLeafAuthentication(c, opts)
}

// Support for bcrypt stored passwords and tokens.
var validBcryptPrefix = regexp.MustCompile(`^\$2[a,b,x,y]{1}\$\d{2}\$.*`)

// isBcrypt checks whether the given password or token is bcrypted.
func isBcrypt(password string) bool {
	if strings.HasPrefix(password, "$") {
		return validBcryptPrefix.MatchString(password)
	}

	return false
}

func comparePasswords(serverPassword, clientPassword string) bool {
	// Check to see if the server password is a bcrypt hash
	if isBcrypt(serverPassword) {
		if err := bcrypt.CompareHashAndPassword([]byte(serverPassword), []byte(clientPassword)); err != nil {
			return false
		}
	} else if serverPassword != clientPassword {
		return false
	}
	return true
}
