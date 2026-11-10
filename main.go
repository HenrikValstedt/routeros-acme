package main

import (
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	_ "time/tzdata" // TZ support in a scratch image
)

// version is set at build time: go build -ldflags "-X main.version=1.0.1".
// The Dockerfile passes it from the VERSION build argument.
var version = "dev"

//go:embed web/index.html
var webFS embed.FS

type app struct {
	store        *Store
	mgr          *Manager
	dataDir      string
	sessions     *sessionStore
	throttle     *throttle // logins, setup, invite/reset tokens
	mailThrottle *throttle // "forgot password" e-mails

	setupCode string // one-time code for first-run admin creation (empty once users exist)

	// reverse proxy support
	proxy        proxyTrust // TRUSTED_PROXIES
	basePath     string     // BASE_PATH, e.g. "/certs" ("" = served at /)
	cookieSecure bool       // COOKIE_SECURE=true forces the Secure cookie flag
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	health := flag.Bool("healthcheck", false, "probe the local web server and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("routeros-acme", version)
		return
	}
	listen := env("LISTEN", ":8080")
	if *health {
		os.Exit(healthcheck(listen))
	}
	log.SetFlags(log.LstdFlags)
	log.Printf("RouterOS ACME %s", version)

	dataDir := env("DATA_DIR", "/data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Fatal(err)
	}
	store, err := OpenStore(dataDir)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	sl, err := loadSealer(dataDir)
	if err != nil {
		log.Fatalf("secret key: %v", err)
	}
	a := &app{store: store, mgr: NewManager(store, dataDir), dataDir: dataDir,
		sessions: &sessionStore{m: map[string]session{}}}
	a.throttle, a.mailThrottle = newThrottle(), newThrottle()
	a.mgr.sealer = sl
	if a.proxy, err = parseTrustedProxies(os.Getenv("TRUSTED_PROXIES")); err != nil {
		log.Fatal(err)
	}
	if a.basePath, err = normalizeBasePath(os.Getenv("BASE_PATH")); err != nil {
		log.Fatal(err)
	}
	a.cookieSecure = strings.EqualFold(os.Getenv("COOKIE_SECURE"), "true")
	if a.proxy.enabled() {
		log.Printf("trusting X-Forwarded-For/-Proto from: %s", a.proxy)
	}
	if err := a.initUsers(); err != nil {
		log.Fatal(err)
	}
	go a.mgr.Scheduler()

	srv := &http.Server{
		Addr: listen, Handler: withBasePath(a.basePath, a.routes()),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second,
	}
	log.Printf("web UI listening on %s%s/", listen, a.basePath)
	log.Fatal(srv.ListenAndServe())
}

func healthcheck(listen string) int {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return 1
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	page, _ := webFS.ReadFile("web/index.html")
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	})

	// public
	mux.HandleFunc("GET /api/session", a.getSession)
	mux.HandleFunc("POST /api/setup", a.postSetup)
	mux.HandleFunc("POST /api/login", a.postLogin)
	mux.HandleFunc("POST /api/invite/check", a.checkInvite)
	mux.HandleFunc("POST /api/invite/accept", a.acceptInvite)
	mux.HandleFunc("POST /api/forgot", a.forgotPassword)
	mux.HandleFunc("POST /api/reset", a.resetPassword)

	// any logged-in user (viewer or admin)
	mux.HandleFunc("POST /api/logout", a.postLogout)
	mux.HandleFunc("PUT /api/me/password", a.need("", a.putMyPassword))
	mux.HandleFunc("PUT /api/me", a.need("", a.putMe))
	mux.HandleFunc("GET /api/state", a.need("", a.getState))
	mux.HandleFunc("GET /api/logs", a.need("", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, a.mgr.Logs()) }))

	// admins only
	adm := func(pattern string, h http.HandlerFunc) { mux.HandleFunc(pattern, a.need(RoleAdmin, h)) }
	adm("PUT /api/settings", a.putSettings)
	adm("POST /api/run", func(w http.ResponseWriter, r *http.Request) {
		a.mgr.logf("check requested by %s", currentUser(r).Username)
		a.mgr.Trigger()
		writeJSON(w, "ok")
	})
	adm("POST /api/certs", a.saveCert)
	adm("DELETE /api/certs/{id}", a.deleteCert)
	adm("POST /api/certs/{id}/issue", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		a.mgr.logf("renewal of certificate %s requested by %s", id, currentUser(r).Username)
		a.mgr.Go(func() { a.mgr.issue(id); a.mgr.deployOutdated() })
		writeJSON(w, "queued")
	})
	adm("POST /api/routers", a.saveRouter)
	adm("DELETE /api/routers/{id}", a.deleteRouter)
	adm("POST /api/routers/{id}/deploy", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		a.mgr.logf("deploy to %q requested by %s", a.devName(id), currentUser(r).Username)
		a.mgr.Go(func() { a.mgr.deploy(id) })
		writeJSON(w, "queued")
	})
	adm("POST /api/routers/{id}/test", func(w http.ResponseWriter, r *http.Request) {
		info, err := a.mgr.test(r.PathValue("id"))
		if err != nil {
			fail(w, 400, err)
			return
		}
		writeJSON(w, info)
	})
	adm("POST /api/routers/{id}/rotate", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		a.mgr.logf("password rotation for %q requested by %s", a.devName(id), currentUser(r).Username)
		a.mgr.Go(func() {
			if err := a.mgr.rotate(id); err != nil {
				a.mgr.logf("password rotation failed: %v", err)
			}
		})
		writeJSON(w, "queued")
	})
	adm("POST /api/devices/probe", a.probeDevice)
	adm("POST /api/devices/enroll", a.enrollDevice)
	adm("GET /api/users", a.listUsers)
	adm("POST /api/users", a.saveUser)
	adm("DELETE /api/users/{id}", a.deleteUser)
	adm("GET /api/invites", a.listInvites)
	adm("POST /api/invites", a.createInvite)
	adm("DELETE /api/invites/{id}", a.deleteInvite)
	adm("PUT /api/mail", a.putMail)
	adm("POST /api/mail/test", a.testMail)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// JSON-only API: blocks cross-site form posts (CSRF).
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}
		mux.ServeHTTP(w, r)
	})
}

func (a *app) devName(id string) string {
	if r := a.store.Snapshot().router(id); r != nil {
		return r.Name
	}
	return id
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	http.Error(w, err.Error(), code)
}

// ---- views (secrets are never sent to the browser) ----

type settingsView struct {
	Settings
	HasCFToken bool `json:"hasCfToken"`
}

type routerView struct {
	Router
	Enrolled bool `json:"enrolled"`
}

func (a *app) getState(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Snapshot()
	sv := settingsView{Settings: cfg.Settings, HasCFToken: cfg.Settings.CFToken != ""}
	sv.CFToken, sv.AdminHash = "", ""
	routers := make([]routerView, 0, len(cfg.Routers))
	for _, r := range cfg.Routers {
		v := routerView{Router: *r, Enrolled: r.enrolled()}
		v.Secret, v.Pending = "", ""
		routers = append(routers, v)
	}
	if cfg.Certs == nil {
		cfg.Certs = []*Cert{}
	}
	writeJSON(w, map[string]any{
		"settings": sv, "certs": cfg.Certs, "routers": routers, "mail": mailViewOf(cfg.Mail),
		"busy": a.mgr.Busy(), "now": time.Now(), "me": viewOf(currentUser(r)), "version": version,
	})
}

func (a *app) putSettings(w http.ResponseWriter, r *http.Request) {
	var in Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, err)
		return
	}
	in.Email = strings.TrimSpace(in.Email)
	switch {
	case in.Email != "" && !strings.Contains(in.Email, "@"):
		fail(w, 400, errors.New("invalid e-mail"))
		return
	case keyTypes[in.KeyType] == "":
		fail(w, 400, errors.New("invalid key type"))
		return
	case in.RenewDays < 1 || in.RenewDays > 60:
		fail(w, 400, errors.New("renew days must be 1-60"))
		return
	case in.CheckHours < 1 || in.CheckHours > 168:
		fail(w, 400, errors.New("check interval must be 1-168 hours"))
		return
	}
	err := a.store.Update(func(c *Config) error {
		s := &c.Settings
		s.Email, s.Staging, s.KeyType = in.Email, in.Staging, in.KeyType
		s.RenewDays, s.CheckHours, s.DNSResolvers = in.RenewDays, in.CheckHours, strings.TrimSpace(in.DNSResolvers)
		if t := strings.TrimSpace(in.CFToken); t != "" {
			s.CFToken = t
		}
		for _, x := range c.Certs {
			x.LastError = "" // settings may have fixed the problem: allow an immediate retry
		}
		return nil
	})
	if err != nil {
		fail(w, 500, err)
		return
	}
	a.mgr.Trigger()
	writeJSON(w, "ok")
}

func normalizeDomains(in []string) ([]string, error) {
	var out []string
	for _, d := range in {
		for _, d := range splitList(d) {
			d = strings.ToLower(strings.TrimSuffix(d, "."))
			if strings.ContainsAny(d, "/:@ ") || !strings.Contains(d, ".") {
				return nil, fmt.Errorf("invalid domain %q", d)
			}
			if !slices.Contains(out, d) {
				out = append(out, d)
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one domain is required")
	}
	return out, nil
}

func (a *app) saveCert(w http.ResponseWriter, r *http.Request) {
	var in Cert
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, err)
		return
	}
	domains, err := normalizeDomains(in.Domains)
	if err != nil {
		fail(w, 400, err)
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = domains[0]
	}
	err = a.store.Update(func(c *Config) error {
		if in.ID == "" {
			c.Certs = append(c.Certs, &Cert{ID: newID(), Name: name, Domains: domains})
			return nil
		}
		x := c.cert(in.ID)
		if x == nil {
			return errors.New("not found")
		}
		if !slices.Equal(x.Domains, domains) {
			x.NotAfter = time.Time{} // force re-issue with the new names
		}
		x.Name, x.Domains, x.LastError = name, domains, ""
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	a.mgr.Trigger()
	writeJSON(w, "ok")
}

func (a *app) deleteCert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.store.Update(func(c *Config) error {
		for _, rt := range c.Routers {
			if rt.CertID == id {
				return fmt.Errorf("certificate is used by router %q", rt.Name)
			}
		}
		c.Certs = slices.DeleteFunc(c.Certs, func(x *Cert) bool { return x.ID == id })
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	_ = os.RemoveAll(filepath.Join(a.dataDir, "certs", sanitize(id)))
	writeJSON(w, "ok")
}

// saveRouter edits what is deployed to an (enrolled) device. Access details only
// change through enrollment.
func (a *app) saveRouter(w http.ResponseWriter, r *http.Request) {
	var in Router
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, err)
		return
	}
	var svcs []string
	for _, s := range in.Services {
		if serviceNames[s] && !slices.Contains(svcs, s) {
			svcs = append(svcs, s)
		}
	}
	err := a.store.Update(func(c *Config) error {
		if in.CertID != "" && c.cert(in.CertID) == nil {
			return errors.New("unknown certificate")
		}
		x := c.router(in.ID)
		if x == nil {
			return errors.New("not found")
		}
		if n := strings.TrimSpace(in.Name); n != "" {
			x.Name = n
		}
		x.Enabled, x.CertID, x.Services, x.ExtraCmds = in.Enabled, in.CertID, svcs, in.ExtraCmds
		x.DeployedFP = "" // settings changed: push again on next check
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	a.mgr.Trigger()
	writeJSON(w, "ok")
}

// deleteRouter forgets a device. With admin SSH credentials it also removes the
// service account (and its group, if unused) from the device.
func (a *app) deleteRouter(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Cleanup *sshLogin `json:"cleanup"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	dev := a.store.Snapshot().router(id)
	if dev == nil {
		fail(w, 404, errors.New("not found"))
		return
	}
	msg := "removed from RouterOS ACME"
	if in.Cleanup != nil {
		l := *in.Cleanup
		in.Cleanup.wipe()
		l.Host, l.HostKey = dev.Host, dev.SSHHostKey
		if l.Port == 0 {
			l.Port = dev.SSHPort
		}
		err := cleanupDevice(l, dev.ServiceUser)
		l.wipe()
		if err != nil {
			fail(w, 400, fmt.Errorf("cleanup on the device failed (device not removed): %w", err))
			return
		}
		msg = fmt.Sprintf("removed; service account %q deleted from the device", dev.ServiceUser)
	}
	_ = a.store.Update(func(c *Config) error {
		c.Routers = slices.DeleteFunc(c.Routers, func(x *Router) bool { return x.ID == id })
		return nil
	})
	a.mgr.logf("device %q %s by %s", dev.Name, msg, currentUser(r).Username)
	writeJSON(w, msg)
}

type enrollRequest struct {
	sshLogin
	ID          string   `json:"id"` // set when re-enrolling an existing device
	Name        string   `json:"name"`
	APIPort     int      `json:"apiPort"`
	ServiceUser string   `json:"serviceUser"`
	AllowedFrom string   `json:"allowedFrom"`
	CertID      string   `json:"certId"`
	Services    []string `json:"services"`
	ExtraCmds   string   `json:"extraCommands"`
	Enabled     bool     `json:"enabled"`
}

func (e *enrollRequest) validate() error {
	e.Host, e.User = strings.TrimSpace(e.Host), strings.TrimSpace(e.User)
	if e.ServiceUser = strings.TrimSpace(e.ServiceUser); e.ServiceUser == "" {
		e.ServiceUser = defaultServiceUser
	}
	if e.Port == 0 {
		e.Port = 22
	}
	switch {
	case e.Host == "" || strings.ContainsAny(e.Host, " /\\\"'"):
		return errors.New("host is required")
	case e.User == "":
		return errors.New("admin username is required")
	case e.Password == "" && strings.TrimSpace(e.PrivateKey) == "":
		return errors.New("admin password or private key is required")
	case e.Port < 1 || e.Port > 65535 || e.APIPort < 0 || e.APIPort > 65535:
		return errors.New("invalid port")
	case !validServiceUser(e.ServiceUser):
		return errors.New("invalid service account name")
	case strings.EqualFold(e.ServiceUser, e.User):
		return errors.New("the service account must not be the admin account you log in with")
	}
	if e.AllowedFrom = strings.TrimSpace(e.AllowedFrom); e.AllowedFrom != "" {
		if _, err := netip.ParsePrefix(e.AllowedFrom); err != nil {
			if _, err := netip.ParseAddr(e.AllowedFrom); err != nil {
				return errors.New("allowed-from must be an IP address or CIDR, or empty")
			}
		}
	}
	return nil
}

func (a *app) probeDevice(w http.ResponseWriter, r *http.Request) {
	var in enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, err)
		return
	}
	defer in.wipe()
	if err := in.validate(); err != nil {
		fail(w, 400, err)
		return
	}
	in.HostKey = ""
	res, err := probeDevice(in.sshLogin, in.ServiceUser)
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSON(w, res)
}

func (a *app) enrollDevice(w http.ResponseWriter, r *http.Request) {
	me := currentUser(r)
	var in enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, err)
		return
	}
	defer in.wipe()
	if err := in.validate(); err != nil {
		fail(w, 400, err)
		return
	}
	if in.HostKey == "" {
		fail(w, 400, errors.New("confirm the device's SSH host key first (Connect step)"))
		return
	}
	cfg := a.store.Snapshot()
	if in.CertID != "" && cfg.cert(in.CertID) == nil {
		fail(w, 400, errors.New("unknown certificate"))
		return
	}
	if in.ID != "" && cfg.router(in.ID) == nil {
		fail(w, 404, errors.New("device not found"))
		return
	}
	var svcs []string
	for _, s := range in.Services {
		if serviceNames[s] && !slices.Contains(svcs, s) {
			svcs = append(svcs, s)
		}
	}

	a.mgr.logf("enrolling %s (%s) – started by %s", in.Host, in.Name, me.Username)
	res, err := enrollDevice(in.sshLogin, enrollOpts{APIPort: in.APIPort, ServiceUser: in.ServiceUser, AllowedFrom: in.AllowedFrom})
	in.wipe()
	if err != nil {
		a.mgr.logf("enrollment of %s failed: %v", in.Host, err)
		writeJSON(w, map[string]any{"ok": false, "steps": res.Steps, "error": err.Error()})
		return
	}
	nr := res.Router
	nr.Secret = a.mgr.sealer.seal(nr.Secret)
	nr.EnrolledBy = me.Username
	nr.LastSeen = time.Now()
	id := in.ID
	err = a.store.Update(func(c *Config) error {
		x := c.router(id)
		if x == nil {
			x = &Router{ID: newID()}
			c.Routers = append(c.Routers, x)
			id = x.ID
		}
		keep := *x
		*x = nr
		x.ID = keep.ID
		x.Name = strings.TrimSpace(in.Name)
		if x.Name == "" {
			x.Name = nr.Identity
		}
		if x.Name == "" {
			x.Name = nr.Host
		}
		x.Enabled, x.CertID, x.Services, x.ExtraCmds = in.Enabled, in.CertID, svcs, in.ExtraCmds
		return nil
	})
	if err != nil {
		fail(w, 500, err)
		return
	}
	a.mgr.logf("device %s (%s) enrolled by %s: api-ssl :%d, service account %q", in.Host, nr.Identity, me.Username, nr.APIPort, nr.ServiceUser)
	a.mgr.Trigger()
	writeJSON(w, map[string]any{"ok": true, "steps": res.Steps, "id": id})
}
