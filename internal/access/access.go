// Package access supplies bounded, revocable local access policy. No management
// HTTP endpoint is exposed; callers replace validated configuration explicitly.
package access

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrConfig  = errors.New("invalid access configuration")
	ErrDenied  = errors.New("access denied")
	ErrLimited = errors.New("access rate or concurrency limit reached")
	ErrQuota   = errors.New("access quota exhausted")
	ErrState   = errors.New("access state unavailable")
)

const maxUsers = 1024
const maxAccounts = 4096
const reservation = int64(1 << 20)

type User struct {
	ID                string  `json:"id"`
	Username          string  `json:"username"`
	Password          string  `json:"password"`
	Disabled          bool    `json:"disabled,omitempty"`
	MaxRequests       int     `json:"max_requests,omitempty"`
	MaxTunnels        int     `json:"max_tunnels,omitempty"`
	RequestsPerSecond float64 `json:"requests_per_second,omitempty"`
	Burst             int     `json:"burst,omitempty"`
	QuotaBytes        int64   `json:"quota_bytes,omitempty"` // Combined target upload/download; 0 is unlimited.
}
type Document struct {
	Version           int     `json:"v"`
	AttemptsPerSecond float64 `json:"attempts_per_second,omitempty"`
	AttemptBurst      int     `json:"attempt_burst,omitempty"`
	MaxRequests       int     `json:"max_requests,omitempty"`
	Users             []User  `json:"users"`
}
type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) take(now time.Time, rate float64, burst int) bool {
	if b.last.IsZero() {
		b.tokens = float64(burst)
	} else {
		b.tokens = math.Min(float64(burst), b.tokens+math.Max(0, now.Sub(b.last).Seconds())*rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type account struct {
	charged, available, inflight, used int64
	requests, tunnels                  int
	rate                               bucket
}
type grant struct {
	owner              *Controller
	config             User // Password and Username are removed after digesting.
	userHash, passHash [32]byte
	ctx                context.Context
	cancel             context.CancelFunc
	serial             uint64
	account            *account
}
type Controller struct {
	mu             sync.Mutex
	users          map[[32]byte]*grant
	accounts       map[string]*account
	attempt        bucket
	policy         Document
	serial         uint64
	active         int
	closed, failed bool
	statePath      string
	unlock         func()
	rejected       uint64
}
type Stats struct {
	ID             string `json:"id"`
	Disabled       bool   `json:"disabled"`
	ActiveRequests int    `json:"active_requests"`
	ActiveTunnels  int    `json:"active_tunnels"`
	Bytes          int64  `json:"bytes_this_process"`
	ChargedBytes   int64  `json:"charged_bytes"`
	QuotaBytes     int64  `json:"quota_bytes"`
}
type Snapshot struct {
	Persistent  bool    `json:"persistent"`
	Users       []Stats `json:"users"`
	Rejected    uint64  `json:"rejected_requests"`
	StateFailed bool    `json:"state_failed"`
}

func validID(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func normalize(d Document) (Document, error) {
	if d.Version != 1 || len(d.Users) > maxUsers {
		return d, ErrConfig
	}
	if d.AttemptsPerSecond == 0 {
		d.AttemptsPerSecond = 200
	}
	if d.AttemptBurst == 0 {
		d.AttemptBurst = 400
	}
	if d.MaxRequests == 0 {
		d.MaxRequests = 1024
	}
	if !validRate(d.AttemptsPerSecond, d.AttemptBurst) || d.MaxRequests < 1 || d.MaxRequests > 65536 {
		return d, ErrConfig
	}
	ids := map[string]bool{}
	names := map[string]bool{}
	d.Users = append([]User(nil), d.Users...)
	for i := range d.Users {
		u := &d.Users[i]
		if !validID(u.ID) || ids[u.ID] || names[u.Username] || len(u.Username) < 1 || len(u.Username) > 256 || len(u.Password) < 24 || len(u.Password) > 1024 || u.QuotaBytes < 0 || u.QuotaBytes > 1<<60 {
			return d, ErrConfig
		}
		for _, c := range u.Username {
			if c < 33 || c > 126 || c == ':' {
				return d, ErrConfig
			}
		}
		ids[u.ID] = true
		names[u.Username] = true
		if u.MaxRequests == 0 {
			u.MaxRequests = 128
		}
		if u.MaxTunnels == 0 {
			u.MaxTunnels = 32
		}
		if u.RequestsPerSecond == 0 {
			u.RequestsPerSecond = 100
		}
		if u.Burst == 0 {
			u.Burst = 200
		}
		if u.MaxRequests < 1 || u.MaxRequests > 4096 || u.MaxTunnels < 1 || u.MaxTunnels > 4096 || !validRate(u.RequestsPerSecond, u.Burst) {
			return d, ErrConfig
		}
	}
	return d, nil
}
func validRate(rate float64, burst int) bool {
	return !math.IsNaN(rate) && !math.IsInf(rate, 0) && rate >= 0.1 && rate <= 10000 && burst >= 1 && burst <= 20000
}
func Validate(d Document) error { _, err := normalize(d); return err }

// New owns an exclusive state-file lock until Close. Empty statePath explicitly
// chooses process-local accounting (useful to SDK hosts with their own lifecycle).
func New(d Document, statePath string) (*Controller, error) {
	if _, err := normalize(d); err != nil {
		return nil, err
	}
	c := &Controller{accounts: map[string]*account{}, statePath: statePath}
	if statePath != "" {
		unlock, err := lockState(statePath)
		if err != nil {
			return nil, ErrState
		}
		c.unlock = unlock
		charged, err := ReadUsage(statePath)
		if err != nil {
			unlock()
			return nil, ErrState
		}
		for id, n := range charged {
			c.accounts[id] = &account{charged: n}
		}
	}
	if err := c.Replace(d); err != nil {
		if c.unlock != nil {
			c.unlock()
		}
		return nil, err
	}
	if statePath != "" {
		c.mu.Lock()
		err := c.persist()
		c.mu.Unlock()
		if err != nil {
			c.Close()
			return nil, ErrState
		}
	}
	return c, nil
}

// Replace is transactional. Unchanged identities retain their generation;
// changed/removed users are revoked. Quota/rate/concurrency accounting survives
// rotation and removal, including outstanding work from the prior generation.
func (c *Controller) Replace(d Document) error {
	d, err := normalize(d)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.failed {
		return ErrState
	}
	additions := 0
	for _, u := range d.Users {
		if c.accounts[u.ID] == nil {
			additions++
		}
	}
	if len(c.accounts)+additions > maxAccounts {
		return ErrConfig
	}
	next := make(map[[32]byte]*grant, len(d.Users))
	keep := map[*grant]bool{}
	for _, u := range d.Users {
		uh, ph := sha256.Sum256([]byte(u.Username)), sha256.Sum256([]byte(u.Password))
		u.Username = ""
		u.Password = ""
		old := c.users[uh]
		if old != nil && old.config == u && old.passHash == ph {
			next[uh] = old
			keep[old] = true
			continue
		}
		a := c.accounts[u.ID]
		if a == nil {
			a = &account{}
			c.accounts[u.ID] = a
		}
		ctx, cancel := context.WithCancel(context.Background())
		c.serial++
		g := &grant{owner: c, config: u, userHash: uh, passHash: ph, ctx: ctx, cancel: cancel, serial: c.serial, account: a}
		if u.Disabled {
			cancel()
		}
		next[uh] = g
	}
	for _, g := range c.users {
		if !keep[g] {
			g.cancel()
		}
	}
	c.users = next
	d.Users = nil
	c.policy = d
	return nil
}
func (c *Controller) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		for _, g := range c.users {
			g.cancel()
		}
		if c.unlock != nil {
			c.unlock()
		}
	}
	return nil
}
func (c *Controller) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Snapshot{Persistent: c.statePath != "", Users: make([]Stats, 0, len(c.users)), Rejected: c.rejected, StateFailed: c.failed}
	for _, g := range c.users {
		a := g.account
		s.Users = append(s.Users, Stats{ID: g.config.ID, Disabled: g.config.Disabled, ActiveRequests: a.requests, ActiveTunnels: a.tunnels, Bytes: a.used, ChargedBytes: a.charged, QuotaBytes: g.config.QuotaBytes})
	}
	sort.Slice(s.Users, func(i, j int) bool { return s.Users[i].ID < s.Users[j].ID })
	return s
}

type grantKey struct{}

func from(ctx context.Context) *grant        { g, _ := ctx.Value(grantKey{}).(*grant); return g }
func Authenticated(ctx context.Context) bool { g := from(ctx); return g != nil && g.ctx.Err() == nil }

// Scope detaches HTTP request cancellation while retaining the authenticated
// owner's revocation lifetime, for paired carriers and retryable bond sessions.
func Scope(ctx context.Context) context.Context {
	if g := from(ctx); g != nil {
		return context.WithValue(g.ctx, grantKey{}, g)
	}
	return context.Background()
}
func Owner(ctx context.Context) string {
	if g := from(ctx); g != nil {
		return g.config.ID + "/" + formatSerial(g.serial)
	}
	return ""
}
func formatSerial(n uint64) string {
	const hex = "0123456789abcdef"
	var b [16]byte
	for i := 15; i >= 0; i-- {
		b[i] = hex[n&15]
		n >>= 4
	}
	return string(b[:])
}

// Begin authenticates one request, enforcing fixed global and per-user bounds.
// Inherited carrier identity must match; clients cannot switch user inside WSS/XHTTP.
func (c *Controller) Begin(r *http.Request) (context.Context, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	deny := func(err error) (context.Context, func(), error) { c.rejected++; return nil, nil, err }
	if c.closed || c.failed {
		return deny(ErrState)
	}
	if !c.attempt.take(time.Now(), c.policy.AttemptsPerSecond, c.policy.AttemptBurst) {
		return deny(ErrDenied)
	}
	h := r.Header.Values("Proxy-Authorization")
	if len(h) != 1 || len(h[0]) > 2048 || len(h[0]) < 7 || !strings.EqualFold(h[0][:6], "Basic ") {
		return deny(ErrDenied)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[0][6:]))
	if err != nil {
		return deny(ErrDenied)
	}
	name, password, ok := strings.Cut(string(raw), ":")
	if !ok {
		return deny(ErrDenied)
	}
	uh, ph := sha256.Sum256([]byte(name)), sha256.Sum256([]byte(password))
	g := c.users[uh]
	expected := [32]byte{}
	if g != nil {
		expected = g.passHash
	}
	valid := subtle.ConstantTimeCompare(ph[:], expected[:])
	if valid != 1 || g == nil || g.config.Disabled {
		return deny(ErrDenied)
	}
	if bound := from(r.Context()); bound != nil && bound != g {
		return deny(ErrDenied)
	}
	a := g.account
	if g.config.QuotaBytes > 0 && a.charged-a.available >= g.config.QuotaBytes {
		return deny(ErrQuota)
	}
	if g.ctx.Err() != nil {
		return deny(ErrDenied)
	}
	if c.active >= c.policy.MaxRequests || a.requests >= g.config.MaxRequests || !a.rate.take(time.Now(), g.config.RequestsPerSecond, g.config.Burst) {
		return deny(ErrLimited)
	}
	c.active++
	a.requests++
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(g.ctx, cancel)
	ctx = context.WithValue(ctx, grantKey{}, g)
	var once sync.Once
	done := func() {
		once.Do(func() {
			stop()
			cancel()
			c.mu.Lock()
			a.requests--
			c.active--
			c.mu.Unlock()
		})
	}
	return ctx, done, nil
}
