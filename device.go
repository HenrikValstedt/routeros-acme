package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	serviceGroup       = "routeros-acme"
	defaultServiceUser = "routeros-acme"
	apiCertName        = "routeros-acme-api"
	managedComment     = "Managed by RouterOS ACME - do not edit"
	minRouterOSMajor   = 7
	rotateEvery        = 30 * 24 * time.Hour
)

// ip services the certificate can be assigned to directly.
var serviceNames = map[string]bool{"www-ssl": true, "api-ssl": true}

// Policies of the service account group: API login only, enough to manage
// certificates, files and ip services, and to change its own password (rotation).
// Everything interactive (ssh, winbox, web, telnet, local console) and anything able
// to manage users/policies, reboot or sniff is denied.
var servicePolicy = []string{"api", "read", "write", "ftp", "sensitive", "password",
	"!local", "!telnet", "!ssh", "!reboot", "!policy", "!test", "!winbox", "!web", "!sniff", "!romon", "!rest-api"}

// ---------------- probe ----------------

type probeResult struct {
	Identity          string   `json:"identity"`
	Board             string   `json:"board"`
	Version           string   `json:"version"`
	HostKey           string   `json:"hostKey"`
	SourceIP          string   `json:"sourceIp"` // the app's address as the router sees it
	APISSLDisabled    bool     `json:"apiSslDisabled"`
	APISSLPort        int      `json:"apiSslPort"`
	APISSLCert        string   `json:"apiSslCert"`
	ServiceUserExists bool     `json:"serviceUserExists"`
	Warnings          []string `json:"warnings"`
}

func rosMajor(version string) int {
	v, _, _ := strings.Cut(version, ".")
	n, _ := strconv.Atoi(v)
	return n
}

func validServiceUser(s string) bool { return usernameRE.MatchString(s) }

// probeDevice logs in with the admin credentials and reads what enrollment needs.
func probeDevice(l sshLogin, serviceUser string) (probeResult, error) {
	var p probeResult
	rc, err := dialSSH(l)
	if err != nil {
		return p, err
	}
	defer rc.Close()
	p.HostKey = rc.hostFP
	script := strings.Join([]string{
		`:put [/system resource get version]`,
		`:put [/system identity get name]`,
		`:put [/system resource get board-name]`,
		`:put [/ip service get api-ssl disabled]`,
		`:put [/ip service get api-ssl port]`,
		`:put [/ip service get api-ssl certificate]`,
		`:local a ""; :foreach i in=[/user active find where via="ssh" and name=` + rosQuote(l.User) + `] do={:set a [/user active get $i address]}; :put $a`,
		`:put [:len [/user find where name=` + rosQuote(serviceUser) + `]]`,
	}, "; ")
	out, err := rc.run(script)
	if err != nil {
		return p, err
	}
	lines := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")
	for len(lines) < 8 {
		lines = append(lines, "")
	}
	p.Version, p.Identity, p.Board = lines[0], lines[1], lines[2]
	p.APISSLDisabled = lines[3] == "true"
	p.APISSLPort, _ = strconv.Atoi(lines[4])
	if c := lines[5]; c != "none" && c != "" {
		p.APISSLCert = c
	}
	p.SourceIP = lines[6]
	p.ServiceUserExists = lines[7] != "0" && lines[7] != ""
	if p.APISSLPort == 0 {
		p.APISSLPort = 8729
	}
	if rosMajor(p.Version) < minRouterOSMajor {
		p.Warnings = append(p.Warnings, fmt.Sprintf("RouterOS %s is not supported – version %d or newer is required.", p.Version, minRouterOSMajor))
	}
	if p.APISSLDisabled {
		p.Warnings = append(p.Warnings, "The api-ssl service is disabled. Enrollment will enable it (on the port below).")
	}
	if p.ServiceUserExists {
		p.Warnings = append(p.Warnings, fmt.Sprintf("A user %q already exists. Enrollment will take it over and give it a new random password.", serviceUser))
	}
	return p, nil
}

// ---------------- enroll ----------------

type enrollOpts struct {
	APIPort     int
	ServiceUser string
	AllowedFrom string // address/CIDR for the service account, "" = any
}

type enrollStep struct {
	Title  string `json:"title"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type enrollResult struct {
	Steps   []enrollStep
	Router  Router // device fields filled in by enrollment
	Version string
}

// bootstrapCert creates the self-signed certificate used for api-ssl when the router
// has none. Its fingerprint is pinned, so no CA is needed.
func bootstrapCert(host, identity string) (certPEM, keyPEM []byte, fp string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048) // RSA for the widest RouterOS TLS compatibility
	if err != nil {
		return nil, nil, "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "RouterOS ACME API " + identity, Organization: []string{"RouterOS ACME"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(20, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, "", err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, certFingerprint(der), nil
}

// enrollDevice sets up the device for API-only management using the admin SSH login once.
func enrollDevice(l sshLogin, o enrollOpts) (res enrollResult, err error) {
	step := func(title string, fn func() (string, error)) error {
		detail, err := fn()
		if err != nil {
			res.Steps = append(res.Steps, enrollStep{title, false, err.Error()})
			return err
		}
		res.Steps = append(res.Steps, enrollStep{title, true, detail})
		return nil
	}
	if o.APIPort == 0 {
		o.APIPort = 8729
	}
	var rc *rosConn
	if err := step("Connect over SSH (one-time admin login)", func() (string, error) {
		var err error
		if rc, err = dialSSH(l); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s@%s, host key %s verified", l.User, l.Host, rc.hostFP), nil
	}); err != nil {
		return res, err
	}
	defer rc.Close()

	var identity, board string
	if err := step("Check RouterOS version", func() (string, error) {
		out, err := rc.run(`:put [/system resource get version]; :put [/system identity get name]; :put [/system resource get board-name]`)
		if err != nil {
			return "", err
		}
		f := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")
		for len(f) < 3 {
			f = append(f, "")
		}
		res.Version, identity, board = f[0], f[1], f[2]
		if rosMajor(res.Version) < minRouterOSMajor {
			return "", fmt.Errorf("RouterOS %s is too old, version %d or newer is required", res.Version, minRouterOSMajor)
		}
		return fmt.Sprintf("RouterOS %s on %s (%s)", res.Version, board, identity), nil
	}); err != nil {
		return res, err
	}

	var pin string
	if err := step("Secure the API with a TLS certificate", func() (string, error) {
		cur, _ := rc.run(`:put [/ip service get api-ssl certificate]`)
		if cur != "" && cur != "none" {
			fp, err := rc.run(fmt.Sprintf(`:put [/certificate get [find where name=%s] fingerprint]; :put [/certificate get [find where name=%s] private-key]`, rosQuote(cur), rosQuote(cur)))
			f := strings.Fields(fp)
			if err == nil && len(f) == 2 && f[1] == "true" && len(f[0]) == 64 {
				pin = strings.ToLower(f[0])
				return fmt.Sprintf("api-ssl already uses certificate %q – keeping it and pinning its fingerprint", cur), nil
			}
		}
		certPEM, keyPEM, fp, err := bootstrapCert(l.Host, identity)
		if err != nil {
			return "", err
		}
		base := apiCertName + "-" + time.Now().UTC().Format("20060102T150405")
		defer func() { _, _ = rc.run(fmt.Sprintf(`/file remove [find where name~%s]`, rosQuote(base))) }()
		if err := rc.upload(base+".crt", certPEM); err != nil {
			return "", err
		}
		if err := rc.upload(base+".key", keyPEM); err != nil {
			return "", err
		}
		time.Sleep(time.Second)
		// leftovers of an interrupted earlier attempt (e.g. a certificate without its key)
		_, _ = rc.run(fmt.Sprintf(`/certificate remove [find where name~%s and private-key=no]`, rosQuote("^"+apiCertName)))
		for _, f := range []string{base + ".crt", base + ".key"} {
			if _, err := rc.run(fmt.Sprintf(`/certificate import file-name=%s passphrase=""`, rosQuote(f))); err != nil {
				return "", err
			}
		}
		find := fmt.Sprintf(`[find where fingerprint=%s]`, rosQuote(fp))
		if pk, _ := rc.run(fmt.Sprintf(`:put [/certificate get %s private-key]`, find)); pk != "true" {
			return "", errors.New("the API certificate was imported without its private key")
		}
		// replace an older API certificate from a previous enrollment
		_, _ = rc.run(fmt.Sprintf(`/certificate remove [find where name=%s]`, rosQuote(apiCertName)))
		if _, err := rc.run(fmt.Sprintf(`/certificate set %s name=%s`, find, rosQuote(apiCertName))); err != nil {
			return "", err
		}
		pin = fp
		return fmt.Sprintf("installed self-signed certificate %q, fingerprint %s… is pinned", apiCertName, fp[:16]), nil
	}); err != nil {
		return res, err
	}

	if err := step("Enable the api-ssl service", func() (string, error) {
		cert, _ := rc.run(`:put [/ip service get api-ssl certificate]`)
		cmd := fmt.Sprintf(`/ip service set api-ssl disabled=no port=%d`, o.APIPort)
		if cert == "" || cert == "none" {
			cmd += " certificate=" + rosQuote(apiCertName)
		}
		if _, err := rc.run(cmd); err != nil {
			return "", err
		}
		return fmt.Sprintf("api-ssl enabled on port %d (plain-text api and other services are not touched)", o.APIPort), nil
	}); err != nil {
		return res, err
	}

	groupExisted := false
	if err := step("Create restricted group "+serviceGroup, func() (string, error) {
		n, _ := rc.run(fmt.Sprintf(`:put [:len [/user group find where name=%s]]`, rosQuote(serviceGroup)))
		groupExisted = n != "0"
		pol := strings.Join(servicePolicy, ",")
		cmd := fmt.Sprintf(`/user group add name=%s policy=%s comment=%s`, rosQuote(serviceGroup), pol, rosQuote(managedComment))
		if groupExisted {
			cmd = fmt.Sprintf(`/user group set [find where name=%s] policy=%s comment=%s`, rosQuote(serviceGroup), pol, rosQuote(managedComment))
		}
		if _, err := rc.run(cmd); err != nil {
			return "", err
		}
		return "allowed: API, read/write config, files, certificates, change own password. Denied: SSH, Winbox, WebFig, console, user management, reboot", nil
	}); err != nil {
		return res, err
	}

	secret := randToken(32) // 43 chars, [A-Za-z0-9_-]; known only to this app
	created := false
	cleanup := func() {
		if created {
			_, _ = rc.run(fmt.Sprintf(`/user remove [find where name=%s]`, rosQuote(o.ServiceUser)))
		}
		if !groupExisted {
			_, _ = rc.run(fmt.Sprintf(`/user group remove [find where name=%s]`, rosQuote(serviceGroup)))
		}
	}
	if err := step("Create service account "+o.ServiceUser, func() (string, error) {
		addr := ""
		if o.AllowedFrom != "" {
			addr = " address=" + rosQuote(o.AllowedFrom)
		} else {
			addr = ` address=""`
		}
		q := rosQuote(o.ServiceUser)
		tmpl := `:if ([:len [/user find where name=%[1]s]] = 0) do={/user add name=%[1]s group=%[2]s password=%[3]s%[4]s comment=%[5]s} else={/user set [find where name=%[1]s] group=%[2]s password=%[3]s%[4]s comment=%[5]s disabled=no}`
		cmd := fmt.Sprintf(tmpl, q, rosQuote(serviceGroup), rosQuote(secret), addr, rosQuote(managedComment))
		shown := fmt.Sprintf(tmpl, q, rosQuote(serviceGroup), `"***"`, addr, rosQuote(managedComment))
		if _, err := rc.runRedacted(cmd, shown); err != nil {
			return "", err
		}
		created = true
		where := "any address"
		if o.AllowedFrom != "" {
			where = o.AllowedFrom + " only"
		}
		return fmt.Sprintf("random 256-bit password (never shown), login allowed from %s", where), nil
	}); err != nil {
		cleanup()
		return res, err
	}

	if err := step("Verify secure API login", func() (string, error) {
		var c *apiClient
		var err error
		// api-ssl may need a moment after being (re)configured
		for i := 0; i < 5; i++ {
			if c, err = dialAPI(l.Host, o.APIPort, []string{pin}); err == nil {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil {
			return "", err
		}
		defer c.Close()
		if err := c.login(o.ServiceUser, secret); err != nil {
			return "", err
		}
		rows, err := c.run("/system/resource/print", "=.proplist=version")
		if err != nil {
			return "", err
		}
		if len(rows) == 0 {
			return "", errors.New("no answer from /system/resource")
		}
		return fmt.Sprintf("logged in over TLS to %s:%d as %s, certificate pin matched", l.Host, o.APIPort, o.ServiceUser), nil
	}); err != nil {
		cleanup()
		res.Steps = append(res.Steps, enrollStep{"Roll back", true, "service account removed again; nothing else needs undoing"})
		return res, err
	}

	res.Router = Router{
		Host: l.Host, APIPort: o.APIPort, ServiceUser: o.ServiceUser, Secret: secret, Pins: []string{pin},
		AllowedFrom: o.AllowedFrom, SSHPort: l.Port, SSHHostKey: rc.hostFP, Identity: identity, Board: board,
		Version: res.Version, EnrolledAt: time.Now(), RotatedAt: time.Now(),
	}
	res.Steps = append(res.Steps, enrollStep{"Forget the admin login", true, "the SSH username and password/key you entered were not saved"})
	return res, nil
}

// cleanupDevice removes the service account and group (used when removing a device).
func cleanupDevice(l sshLogin, serviceUser string) error {
	rc, err := dialSSH(l)
	if err != nil {
		return err
	}
	defer rc.Close()
	if _, err := rc.run(fmt.Sprintf(`/user remove [find where name=%s]`, rosQuote(serviceUser))); err != nil {
		return err
	}
	_, _ = rc.run(fmt.Sprintf(`:if ([:len [/user find where group=%[1]s]] = 0) do={/user group remove [find where name=%[1]s]}`, rosQuote(serviceGroup)))
	return nil
}

// ---------------- API operations (after enrollment) ----------------

// connectDevice opens an authenticated api-ssl session. It returns the password that
// worked and whether it was the pending one (an interrupted rotation that the caller must promote).
func connectDevice(r Router, sl *sealer) (c *apiClient, pw string, usedPending bool, err error) {
	if !r.enrolled() {
		return nil, "", false, errors.New("device is not enrolled – enroll it first")
	}
	candidates := []string{r.Secret}
	if r.Pending != "" {
		candidates = append(candidates, r.Pending)
	}
	for i, sealed := range candidates {
		if pw, err = sl.open(sealed); err != nil {
			return nil, "", false, fmt.Errorf("%w – enroll the device again", err)
		}
		if c, err = dialAPIRetry(r.Host, r.APIPort, r.Pins); err != nil {
			return nil, "", false, err
		}
		if err = c.login(r.ServiceUser, pw); err == nil {
			return c, pw, i == 1, nil
		}
		c.Close()
	}
	return nil, "", false, err
}

// dialAPIRetry retries briefly: right after api-ssl switches certificates RouterOS can,
// for a moment, present the new certificate with the old key (bad handshake signature).
// A pin mismatch is never retried.
func dialAPIRetry(host string, port int, pins []string) (c *apiClient, err error) {
	for i := 0; i < 4; i++ {
		if c, err = dialAPI(host, port, pins); err == nil || strings.Contains(err.Error(), "not the pinned") {
			return c, err
		}
		time.Sleep(time.Duration(i+1) * 750 * time.Millisecond)
	}
	return nil, err
}

func apiGet(c *apiClient, path, prop string) string {
	rows, err := c.run(path+"/print", "=.proplist="+prop)
	if err != nil || len(rows) == 0 {
		return ""
	}
	return rows[0][prop]
}

// deployAPI installs the certificate on the device via api-ssl.
// addPin is called before api-ssl itself is switched to the new certificate.
func deployAPI(c *apiClient, r Router, cert Cert, chain, key []byte, logf func(string, ...any), addPin func(string) error) error {
	prefix := "le-" + cert.ID + "-"
	// timestamp + fingerprint prefix: unique even for two deploys within the same second
	base := prefix + time.Now().UTC().Format("20060102T150405") + "-" + cert.Fingerprint[:8]

	rows, err := c.run("/certificate/print", "?fingerprint="+cert.Fingerprint, "=.proplist=.id,name,private-key")
	if err != nil {
		return fmt.Errorf("list certificates: %w", err)
	}
	var id, name string
	if len(rows) > 0 {
		id, name = rows[0][".id"], rows[0]["name"]
		logf("[%s] certificate already present as %s", r.Name, name)
	} else {
		crt, kf := base+".crt", base+".key"
		// RouterOS writes "/file add" including the file contents to its system log, so
		// the key is uploaded encrypted with a one-time passphrase. The passphrase is only
		// sent in the import command (inside TLS), which RouterOS does not log.
		encKey, pass, err := encryptKey(key)
		if err != nil {
			return err
		}
		logf("[%s] uploading certificate over api-ssl (private key encrypted)", r.Name)
		defer removeFiles(c, base)
		if _, err := c.run("/file/add", "=name="+crt, "=contents="+string(chain)); err != nil {
			return fmt.Errorf("upload certificate: %w", err)
		}
		if _, err := c.run("/file/add", "=name="+kf, "=contents="+string(encKey)); err != nil {
			return fmt.Errorf("upload key: %w", err)
		}
		if _, err := c.run("/certificate/import", "=file-name="+crt, "=passphrase="); err != nil {
			return fmt.Errorf("import certificate: %w", err)
		}
		if _, err := c.run("/certificate/import", "=file-name="+kf, "=passphrase="+pass); err != nil {
			return fmt.Errorf("import key: %w", err)
		}
		rows, err := c.run("/certificate/print", "?fingerprint="+cert.Fingerprint, "=.proplist=.id,name,private-key")
		if err != nil || len(rows) == 0 {
			return fmt.Errorf("imported certificate not found on the device: %v", err)
		}
		id = rows[0][".id"]
		if _, err := c.run("/certificate/set", "=.id="+id, "=name="+base); err != nil {
			return fmt.Errorf("rename certificate: %w", err)
		}
		name = base
		logf("[%s] imported as %s", r.Name, name)
	}
	rows, _ = c.run("/certificate/print", "?.id="+id, "=.proplist=private-key")
	if len(rows) == 0 || rows[0]["private-key"] != "true" {
		return fmt.Errorf("certificate %s on the device has no private key", name)
	}

	for _, svc := range r.Services {
		if !serviceNames[svc] {
			continue
		}
		if svc == "api-ssl" {
			if err := addPin(cert.Fingerprint); err != nil {
				return err
			}
		}
		if _, err := c.run("/ip/service/set", "=numbers="+svc, "=certificate="+name); err != nil {
			return fmt.Errorf("set %s certificate: %w", svc, err)
		}
		logf("[%s] %s now uses %s", r.Name, svc, name)
	}

	if src := strings.TrimSpace(strings.ReplaceAll(r.ExtraCmds, "{{cert}}", name)); src != "" {
		if err := runScript(c, src); err != nil {
			return fmt.Errorf("extra commands: %w", err)
		}
		logf("[%s] extra commands ran", r.Name)
	}

	// remove older certificates this app installed for the same cert
	all, err := c.run("/certificate/print", "=.proplist=.id,name,fingerprint")
	if err == nil {
		var old []string
		for _, x := range all {
			if strings.HasPrefix(x["name"], prefix) && !strings.HasPrefix(x["name"], name) && x["fingerprint"] != cert.Fingerprint {
				old = append(old, x[".id"])
			}
		}
		if len(old) > 0 {
			if _, err := c.run("/certificate/remove", "=numbers="+strings.Join(old, ",")); err != nil {
				logf("[%s] warning: could not remove old certificates: %v", r.Name, err)
			} else {
				logf("[%s] removed %d old certificate(s)", r.Name, len(old))
			}
		}
	}
	return nil
}

// encryptKey wraps a PEM private key in OpenSSL-style AES-256 encryption with a random
// one-time passphrase (RouterOS imports this format).
func encryptKey(keyPEM []byte) ([]byte, string, error) {
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, "", errors.New("private key: no PEM data")
	}
	pass := randToken(32)
	//lint:ignore SA1019 legacy PEM encryption is what RouterOS understands; the passphrase is random and single-use
	enc, err := x509.EncryptPEMBlock(rand.Reader, blk.Type, blk.Bytes, []byte(pass), x509.PEMCipherAES256) //nolint:staticcheck
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(enc), pass, nil
}

func removeFiles(c *apiClient, base string) {
	rows, err := c.run("/file/print", "=.proplist=.id,name")
	if err != nil {
		return
	}
	var ids []string
	for _, f := range rows {
		if strings.Contains(f["name"], base) {
			ids = append(ids, f[".id"])
		}
	}
	if len(ids) > 0 {
		_, _ = c.run("/file/remove", "=numbers="+strings.Join(ids, ","))
	}
}

// runScript runs RouterOS script lines through a temporary /system script.
func runScript(c *apiClient, src string) error {
	name := "routeros-acme-tmp-" + randToken(4)
	if _, err := c.run("/system/script/add", "=name="+name, "=source="+src, "=policy=read,write,sensitive,ftp",
		"=dont-require-permissions=no", "=comment="+managedComment); err != nil {
		return err
	}
	defer func() { _, _ = c.run("/system/script/remove", "=numbers="+name) }()
	_, err := c.run("/system/script/run", "=number="+name)
	return err
}

// rotatePassword gives the service account a new password.
func rotatePassword(c *apiClient, oldPw, newPw string) error {
	_, err := c.run("/password", "=old-password="+oldPw, "=new-password="+newPw, "=confirm-new-password="+newPw)
	return err
}

func uniq(s []string) []string {
	var out []string
	for _, x := range s {
		if x != "" && !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}
