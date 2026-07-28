package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"
)

// watchConfig reloads on file change and on SIGHUP. A configuration that does
// not parse or validate is rejected and the previous one keeps running - a bad
// edit must never take the server down, because a restart would log everyone
// out.
func (s *Server) watchConfig(path string) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	last := statOf(path)

	for {
		select {
		case <-s.stop:
			return

		case <-hup:
			s.reload(path, "sighup")

		case <-ticker.C:
			cur := statOf(path)
			if cur == last {
				continue
			}
			last = cur
			s.reload(path, "file_changed")
		}
	}
}

// fingerprint captures mtime, size and inode, so an atomic replace (which
// changes the inode without necessarily changing size) is also detected.
type fingerprint struct {
	mtime int64
	size  int64
	ino   uint64
}

func statOf(path string) fingerprint {
	fi, err := os.Stat(path)
	if err != nil {
		return fingerprint{}
	}
	f := fingerprint{mtime: fi.ModTime().UnixNano(), size: fi.Size()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		f.ino = uint64(st.Ino)
	}
	return f
}

func (s *Server) reload(path, reason string) {
	cfg, err := LoadConfig(path)
	if err != nil {
		logError("config_error", map[string]any{
			"reason": reason,
			"error":  err.Error(),
			"note":   "previous configuration remains active",
		})
		return
	}
	old := s.Config()
	s.setConfig(cfg)
	warnShortSecrets(cfg)

	logInfo("config_reloaded", map[string]any{
		"reason":     reason,
		"users":      len(cfg.Users),
		"targets":    countTargets(cfg),
		"prev_users": len(old.Users),
	})
}

func countTargets(c *Config) int {
	n := 0
	for _, u := range c.Users {
		n += len(u.Targets)
	}
	return n
}

// warnShortSecrets reports secrets that cannot be redacted from responses.
// Silence here would be dangerous: the operator would assume protection that
// does not exist.
func warnShortSecrets(c *Config) {
	for _, u := range c.Users {
		if u.redactor == nil || len(u.redactor.Skipped) == 0 {
			continue
		}
		logWarn("short_secret", map[string]any{
			"user":    u.Name,
			"secrets": u.redactor.Skipped,
			"note": "values shorter than 8 bytes are not redacted from responses; " +
				"an upstream that reflects them can leak them to the model",
		})
	}
}
