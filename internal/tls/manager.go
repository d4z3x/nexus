package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/d4z3x/nexus/internal/config"
	"github.com/d4z3x/nexus/internal/db"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

// ProvisionError tracks a failed provisioning attempt with cooldown.
type ProvisionError struct {
	Hostname   string    `json:"hostname"`
	Error      string    `json:"error"`
	FailedAt   time.Time `json:"failed_at"`
	RetryAfter time.Time `json:"retry_after"`
}

type Manager struct {
	cfg   *config.Config
	db    *db.DB
	cache sync.Map // hostname -> *tls.Certificate

	provisioning   sync.Map // hostname -> struct{}
	selfSignedCert *tls.Certificate

	errorsMu sync.RWMutex
	errors   map[string]*ProvisionError // hostname -> error
}

type acmeUser struct {
	email string
	key   crypto.PrivateKey
	reg   *registration.Resource
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.reg }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

func NewManager(cfg *config.Config, database *db.DB) (*Manager, error) {
	m := &Manager{cfg: cfg, db: database, errors: make(map[string]*ProvisionError)}

	sc, err := generateSelfSigned()
	if err != nil {
		return nil, fmt.Errorf("self-signed cert: %w", err)
	}
	m.selfSignedCert = sc

	certs, err := database.ListCerts()
	if err != nil {
		return nil, fmt.Errorf("load certs: %w", err)
	}
	for _, c := range certs {
		full, err := database.GetCert(c.Hostname)
		if err != nil {
			continue
		}
		tlsCert, err := tls.X509KeyPair([]byte(full.CertPEM), []byte(full.KeyPEM))
		if err != nil {
			continue
		}
		m.cache.Store(c.Hostname, &tlsCert)
	}

	if cfg.WildcardDomain {
		go m.provisionWildcards()
	}

	return m, nil
}

func (m *Manager) provisionWildcards() {
	routes, err := m.db.ListRoutes()
	if err != nil {
		log.Printf("[tls] wildcard: failed to list routes: %v", err)
		return
	}

	seen := map[string]bool{}
	for _, r := range routes {
		if !r.TLSEnabled {
			continue
		}
		base := baseDomain(r.Hostname)
		if base == "" || seen[base] {
			continue
		}
		seen[base] = true

		wc := "*." + base
		if _, ok := m.cache.Load(wc); ok {
			continue
		}
		if _, err := m.db.GetCert(wc); err == nil {
			continue
		}
		log.Printf("[tls] provisioning wildcard cert for %s", wc)
		if err := m.provision(wc); err != nil {
			log.Printf("[tls] wildcard provision %s failed: %v", wc, err)
		}
	}
}

func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	hostname := hello.ServerName

	if cached, ok := m.cache.Load(hostname); ok {
		return cached.(*tls.Certificate), nil
	}

	if wc := m.matchWildcard(hostname); wc != "" {
		if cached, ok := m.cache.Load(wc); ok {
			return cached.(*tls.Certificate), nil
		}
	}

	c, err := m.db.GetCert(hostname)
	if err == nil {
		tlsCert, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM))
		if err == nil {
			m.cache.Store(hostname, &tlsCert)
			return &tlsCert, nil
		}
	}

	if wc := m.matchWildcard(hostname); wc != "" {
		c, err := m.db.GetCert(wc)
		if err == nil {
			tlsCert, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM))
			if err == nil {
				m.cache.Store(wc, &tlsCert)
				return &tlsCert, nil
			}
		}
	}

	if wc := m.matchWildcard(hostname); wc != "" {
		m.triggerProvision(wc)
	} else {
		m.triggerProvision(hostname)
	}

	return m.selfSignedCert, nil
}

func (m *Manager) matchWildcard(hostname string) string {
	if !m.cfg.WildcardDomain {
		return ""
	}
	base := baseDomain(hostname)
	if base == "" {
		return ""
	}
	return "*." + base
}

func baseDomain(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// isCoolingDown checks if a hostname is in cooldown from a previous failure.
func (m *Manager) isCoolingDown(hostname string) bool {
	m.errorsMu.RLock()
	defer m.errorsMu.RUnlock()
	if pe, ok := m.errors[hostname]; ok {
		return time.Now().Before(pe.RetryAfter)
	}
	return false
}

func (m *Manager) triggerProvision(hostname string) {
	if m.isCoolingDown(hostname) {
		return
	}
	if _, loaded := m.provisioning.LoadOrStore(hostname, struct{}{}); loaded {
		return
	}
	go func() {
		defer m.provisioning.Delete(hostname)
		if err := m.provision(hostname); err != nil {
			log.Printf("[tls] provision %s failed: %v", hostname, err)
		}
	}()
}

func (m *Manager) provision(hostname string) error {
	log.Printf("[tls] provisioning cert for %s", hostname)

	user, err := m.getOrCreateACMEUser()
	if err != nil {
		m.recordError(hostname, fmt.Errorf("acme user: %w", err), 30*time.Minute)
		return fmt.Errorf("acme user: %w", err)
	}

	legoConfig := lego.NewConfig(user)
	if m.cfg.LEStaging {
		legoConfig.CADirURL = lego.LEDirectoryStaging
	}
	legoConfig.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		m.recordError(hostname, fmt.Errorf("lego client: %w", err), 30*time.Minute)
		return fmt.Errorf("lego client: %w", err)
	}

	cfProvider, err := cloudflare.NewDNSProviderConfig(&cloudflare.Config{
		AuthToken:          m.cfg.CFDNSAPIToken,
		TTL:                120,
		PropagationTimeout: 5 * time.Minute,
		PollingInterval:    10 * time.Second,
	})
	if err != nil {
		m.recordError(hostname, fmt.Errorf("cloudflare provider: %w", err), 30*time.Minute)
		return fmt.Errorf("cloudflare provider: %w", err)
	}

	// Use public resolvers for SOA lookups so local AdGuard DNS doesn't break zone detection.
	if err := client.Challenge.SetDNS01Provider(cfProvider,
		dns01.AddRecursiveNameservers([]string{"1.1.1.1:53", "8.8.8.8:53"}),
	); err != nil {
		m.recordError(hostname, fmt.Errorf("set dns01: %w", err), 30*time.Minute)
		return fmt.Errorf("set dns01: %w", err)
	}

	domains := []string{hostname}
	if strings.HasPrefix(hostname, "*.") {
		baseDomain := hostname[2:]
		domains = []string{hostname, baseDomain}
	}

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}
	cert, err := client.Certificate.Obtain(request)
	if err != nil {
		cooldown := parseRetryAfter(err.Error())
		m.recordError(hostname, fmt.Errorf("obtain cert: %w", err), cooldown)
		return fmt.Errorf("obtain cert: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(cert.Certificate, cert.PrivateKey)
	if err != nil {
		return fmt.Errorf("parse cert: %w", err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse leaf: %w", err)
	}

	isStaging := isStaging(leaf)

	dbCert := &db.Cert{
		Hostname:  hostname,
		CertPEM:   string(cert.Certificate),
		KeyPEM:    string(cert.PrivateKey),
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
		IsStaging: isStaging,
	}
	if err := m.db.UpsertCert(dbCert); err != nil {
		return fmt.Errorf("store cert: %w", err)
	}

	m.cache.Store(hostname, &tlsCert)
	m.clearError(hostname)
	log.Printf("[tls] provisioned cert for %s (expires %s)", hostname, leaf.NotAfter.Format(time.RFC3339))
	return nil
}

func (m *Manager) ForceRenew(hostname string) error {
	m.cache.Delete(hostname)
	m.clearError(hostname)
	return m.provision(hostname)
}

// GetProvisionErrors returns all active provisioning errors.
func (m *Manager) GetProvisionErrors() []ProvisionError {
	m.errorsMu.RLock()
	defer m.errorsMu.RUnlock()
	var out []ProvisionError
	for _, pe := range m.errors {
		out = append(out, *pe)
	}
	return out
}

func (m *Manager) recordError(hostname string, err error, cooldown time.Duration) {
	m.errorsMu.Lock()
	defer m.errorsMu.Unlock()
	m.errors[hostname] = &ProvisionError{
		Hostname:   hostname,
		Error:      err.Error(),
		FailedAt:   time.Now(),
		RetryAfter: time.Now().Add(cooldown),
	}
	log.Printf("[tls] %s in cooldown until %s", hostname, time.Now().Add(cooldown).Format(time.RFC3339))
}

func (m *Manager) clearError(hostname string) {
	m.errorsMu.Lock()
	defer m.errorsMu.Unlock()
	delete(m.errors, hostname)
}

// parseRetryAfter extracts a "retry after <timestamp>" from LE error messages.
// Falls back to 1 hour if not parseable.
var retryAfterRe = regexp.MustCompile(`retry after (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})`)

func parseRetryAfter(errMsg string) time.Duration {
	matches := retryAfterRe.FindStringSubmatch(errMsg)
	if len(matches) == 2 {
		if t, err := time.Parse("2006-01-02 15:04:05", matches[1]); err == nil {
			d := time.Until(t.UTC())
			if d > 0 {
				return d
			}
		}
	}
	return 1 * time.Hour
}

func (m *Manager) StartRenewalLoop(stop <-chan struct{}) {
	time.Sleep(30 * time.Second)
	m.renewExpiring()

	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			m.renewExpiring()
		}
	}
}

func (m *Manager) renewExpiring() {
	certs, err := m.db.ExpiringCerts(30 * 24 * time.Hour)
	if err != nil {
		log.Printf("[tls] renewal check error: %v", err)
		return
	}
	for _, c := range certs {
		if m.isCoolingDown(c.Hostname) {
			log.Printf("[tls] skipping renewal for %s (cooling down)", c.Hostname)
			continue
		}
		log.Printf("[tls] renewing expiring cert for %s", c.Hostname)
		if err := m.provision(c.Hostname); err != nil {
			log.Printf("[tls] renewal failed for %s: %v", c.Hostname, err)
		}
	}
}

func (m *Manager) getOrCreateACMEUser() (*acmeUser, error) {
	email := m.cfg.ACMEEmail

	acct, err := m.db.GetACMEAccount(email)
	if err == nil {
		block, _ := pem.Decode([]byte(acct.KeyPEM))
		if block != nil {
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err == nil {
				user := &acmeUser{email: email, key: key}
				return m.registerUser(user)
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	user := &acmeUser{email: email, key: key}
	user, err = m.registerUser(user)
	if err != nil {
		return nil, err
	}

	keyBytes, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	regJSON := "{}"
	if user.reg != nil {
		regJSON = user.reg.URI
	}

	if err := m.db.UpsertACMEAccount(&db.ACMEAccount{
		Email:        email,
		KeyPEM:       string(keyPEM),
		Registration: regJSON,
	}); err != nil {
		log.Printf("[tls] warning: failed to save ACME account: %v", err)
	}

	return user, nil
}

func (m *Manager) registerUser(user *acmeUser) (*acmeUser, error) {
	legoConfig := lego.NewConfig(user)
	if m.cfg.LEStaging {
		legoConfig.CADirURL = lego.LEDirectoryStaging
	}
	legoConfig.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, err
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	user.reg = reg
	return user, nil
}

func generateSelfSigned() (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nexus-fallback"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tlsCert, nil
}

func isStaging(cert *x509.Certificate) bool {
	for _, org := range cert.Issuer.Organization {
		if strings.Contains(strings.ToUpper(org), "STAGING") {
			return true
		}
	}
	if strings.Contains(strings.ToUpper(cert.Issuer.CommonName), "STAGING") {
		return true
	}
	return false
}
