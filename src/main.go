package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

var (
	version = "0.1.0"
	commit  = "dev"
	built   = "unknown"
)

const defaultConfigPath = "/etc/aegis/config.yaml"

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

type Server struct {
	cfg       atomic.Pointer[Config]
	sessions  *SessionStore
	mcp       *mcpSessions
	transport http.RoundTripper
	stop      chan struct{}

	loginLimiter    *KeyedLimiter
	registerLimiter *KeyedLimiter
}

func (s *Server) Config() *Config     { return s.cfg.Load() }
func (s *Server) setConfig(c *Config) { s.cfg.Store(c) }

func NewServer(cfg *Config) *Server {
	s := &Server{
		sessions: NewSessionStore(),
		mcp:      newMCPSessions(),
		stop:     make(chan struct{}),
	}
	s.setConfig(cfg)
	s.loginLimiter = NewKeyedLimiter(cfg.LoginRateLimit)
	registerRate, _ := ParseRate("20/h")
	s.registerLimiter = NewKeyedLimiter(registerRate)

	s.transport = &http.Transport{
		DialContext:           guardedDialer(10 * time.Second),
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return s
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", s.handleProtectedResource)
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", s.handleProtectedResource)
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.handleAuthServerMetadata)
	mux.HandleFunc("/.well-known/oauth-authorization-server/mcp", s.handleAuthServerMetadata)
	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/mcp", s.handleMCP)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			writeHTTPError(w, http.StatusNotFound, "not found")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "aegis %s\nMCP endpoint: %s\n", version, s.Config().endpoint("/mcp"))
	})

	return securityWrapper(mux)
}

// securityWrapper adds headers that apply to every response.
func securityWrapper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "hashpw":
			os.Exit(cmdHashPassword())
		case "validate":
			path := defaultConfigPath
			if len(args) > 1 {
				path = args[1]
			}
			os.Exit(cmdValidate(path))
		case "version", "-v", "--version":
			fmt.Printf("aegis %s (commit %s, built %s)\n", version, commit, built)
			return
		case "help", "-h", "--help":
			usage()
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
			usage()
			os.Exit(2)
		}
	}
	os.Exit(run())
}

func usage() {
	fmt.Print(`aegis - a secrets firewall for LLM agents

Usage:
  aegis                 Run the server
  aegis validate [path] Validate a configuration file
  aegis hashpw          Read a password and print a bcrypt hash
  aegis version         Print version information

Environment:
  AEGIS_CONFIG      config path (default ` + defaultConfigPath + `)
  AEGIS_LISTEN      listen address (default :2019)
  AEGIS_PUBLIC_URL  external base URL, required
  AEGIS_LOG_LEVEL   debug|info|warn|error
`)
}

func run() int {
	setLogLevel(os.Getenv("AEGIS_LOG_LEVEL"))

	path := os.Getenv("AEGIS_CONFIG")
	if path == "" {
		path = defaultConfigPath
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		logError("config_error", map[string]any{"error": err.Error(), "path": path})
		return 1
	}

	s := NewServer(cfg)
	warnShortSecrets(cfg)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go s.sessions.RunJanitor(s.stop)
	go s.watchConfig(path)
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.mcp.sweep()
			case <-s.stop:
				return
			}
		}
	}()

	logInfo("startup", map[string]any{
		"version":    version,
		"listen":     cfg.Listen,
		"public_url": cfg.Issuer(),
		"users":      len(cfg.Users),
		"targets":    countTargets(cfg),
		"config":     path,
	})

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		logError("shutdown", map[string]any{"error": err.Error()})
		return 1
	case <-sig:
	}

	close(s.stop)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	logInfo("shutdown", map[string]any{"reason": "signal"})
	return 0
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

func cmdHashPassword() int {
	var pw []byte
	var err error

	if term.IsTerminal(int(syscall.Stdin)) {
		fmt.Fprint(os.Stderr, "Password: ")
		pw, err = term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "could not read password")
			return 1
		}
		fmt.Fprint(os.Stderr, "Repeat:   ")
		again, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil || string(again) != string(pw) {
			fmt.Fprintln(os.Stderr, "passwords do not match")
			return 1
		}
	} else {
		buf := make([]byte, 0, 256)
		tmp := make([]byte, 256)
		for {
			n, rerr := os.Stdin.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if rerr != nil {
				break
			}
		}
		pw = []byte(strings.TrimRight(string(buf), "\r\n"))
	}

	if len(pw) == 0 {
		fmt.Fprintln(os.Stderr, "empty password")
		return 1
	}
	h, err := bcrypt.GenerateFromPassword(pw, 12)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hashing failed")
		return 1
	}
	fmt.Printf("bcrypt:%s\n", h)
	return 0
}

func cmdValidate(path string) int {
	cfg, err := LoadConfig(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
		return 1
	}
	fmt.Printf("%s: OK\n", path)
	fmt.Printf("  public_url: %s\n", cfg.Issuer())
	fmt.Printf("  listen:     %s\n", cfg.Listen)
	for _, name := range sortedUserNames(cfg) {
		u := cfg.Users[name]
		fmt.Printf("\n  user %s (allow_any=%v)\n", u.Name, u.AllowAny)
		if len(u.Secrets) > 0 {
			names := make([]string, 0, len(u.Secrets))
			for n := range u.Secrets {
				marker := ""
				if len(u.Secrets[n]) < minRedactLen {
					marker = " (too short to redact)"
				}
				names = append(names, n+marker)
			}
			sortStrings(names)
			fmt.Printf("    secrets: %s\n", strings.Join(names, ", "))
		}
		for _, t := range u.Targets {
			fmt.Printf("    target %-14s %s %s  paths=%s\n",
				t.ID, strings.Join(t.MethodList, ","), t.BaseURL, strings.Join(t.PathSources, ","))
		}
	}
	return 0
}

func sortedUserNames(c *Config) []string {
	names := make([]string, 0, len(c.Users))
	for n := range c.Users {
		names = append(names, n)
	}
	sortStrings(names)
	return names
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
