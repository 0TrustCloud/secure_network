package secure_network

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type ACMEConfig struct {
	Email    string
	CacheDir string
	Domain   string
	Staging  bool
}

func (a ACMEConfig) Enabled() bool {
	return strings.TrimSpace(a.Email) != ""
}

type tlsBundle struct {
	Config  *tls.Config
	Manager *autocert.Manager
}

func resolveTLS(acmeCfg ACMEConfig) (*tlsBundle, error) {
	domain := strings.ToLower(strings.TrimSpace(acmeCfg.Domain))
	if acmeCfg.Enabled() {
		if domain == "" {
			domain = "0trust.cloud"
		}
		return acmeTLSConfig(acmeCfg, domain)
	}
	tlsConfig, err := generateEphemeralTLS(domain)
	if err != nil {
		return nil, err
	}
	log.Printf("[tls] using self-signed certificates (set server.acme.email for Let's Encrypt)")
	return &tlsBundle{Config: tlsConfig}, nil
}

func acmeTLSConfig(acmeCfg ACMEConfig, domain string) (*tlsBundle, error) {
	cacheDir := acmeCfg.CacheDir
	if cacheDir == "" {
		cacheDir = "data/acme"
	}
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Email:  strings.TrimSpace(acmeCfg.Email),
		Cache:  autocert.DirCache(cacheDir),
		HostPolicy: func(_ context.Context, host string) error {
			host = strings.ToLower(strings.TrimSpace(host))
			if host == domain {
				return nil
			}
			if strings.HasSuffix(host, "."+domain) {
				return nil
			}
			return fmt.Errorf("acme/autocert: host %q not under %q", host, domain)
		},
	}
	if acmeCfg.Staging {
		m.Client = &acme.Client{DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"}
	}
	tlsConfig := m.TLSConfig()
	tlsConfig.MinVersion = tls.VersionTLS12
	tlsConfig.NextProtos = []string{"h3", "h2", "http/1.1", "secure-overlay"}

	log.Printf("[tls] ACME enabled — Let's Encrypt certs for *.%s (cache: %s)", domain, cacheDir)
	for _, host := range []string{domain, "tunnel." + domain} {
		go prefetchACMECert(m, host)
	}
	return &tlsBundle{Config: tlsConfig, Manager: m}, nil
}

func prefetchACMECert(m *autocert.Manager, host string) {
	if _, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: host}); err != nil {
		log.Printf("[tls] ACME prefetch %s: %v", host, err)
		return
	}
	log.Printf("[tls] ACME certificate ready for %s", host)
}