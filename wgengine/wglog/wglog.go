// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wglog contains logging helpers for wireguard-go.
package wglog

import (
	"encoding/base64"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/device"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/wgcfg"
)

// A Logger is a wireguard-go log wrapper that cleans up and rewrites log lines.
// It can be modified at run time to adjust to new wireguard-go configurations.
type Logger struct {
	DeviceLogger *device.Logger
	replacer     atomic.Value // of *strings.Replacer
}

// NewLogger creates a new logger for use with wireguard-go.
// This logger silences repetitive/unhelpful noisy log lines
// and rewrites peer keys from wireguard-go into Tailscale format.
func NewLogger(logf logger.Logf) *Logger {
	ret := new(Logger)

	unlimitLogf := func(format string, args ...interface{}) {
		logf("<RATELIMITED>"+format, args...)
	}

	fixup := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		if strings.Contains(msg, "Routine:") && !strings.Contains(msg, "receive incoming") {
			// wireguard-go logs as it starts and stops routines.
			// Drop those; there are a lot of them, and they're just noise.
			return
		}
		if strings.Contains(msg, "Failed to send data packet") {
			// Drop. See https://github.com/tailscale/tailscale/issues/1239.
			return
		}
		if strings.Contains(msg, "Interface up requested") || strings.Contains(msg, "Interface down requested") {
			// Drop. Logs 1/s constantly while the tun device is open.
			// See https://github.com/tailscale/tailscale/issues/1388.
			return
		}
		r := ret.replacer.Load()
		if r == nil {
			// No replacements specified; log as originally planned.
			unlimitLogf(format, args...)
			return
		}
		// Do the replacements.
		new := r.(*strings.Replacer).Replace(msg)
		if new == msg {
			// No replacements. Log as originally planned.
			unlimitLogf(format, args...)
			return
		}
		// We made some replacements. Log the new version.
		// This changes the format string,
		// which is somewhat unfortunate as it impacts rate limiting,
		// but there's not much we can do about that.
		unlimitLogf("%s", new)
	}

	// Idea: We could actually get fancier here. For example, we could
	// check each wireguard logline for a nodekey prefix, and rate
	// limit based on the nodekey rather than the specific message.
	rlogf := logger.RateLimitedFn(fixup, 5*time.Second, 5, 100)

	ret.DeviceLogger = &device.Logger{
		Verbosef: logger.WithPrefix(rlogf, "[v2] "),
		Errorf:   rlogf,
	}
	return ret
}

// SetPeers adjusts x to rewrite the peer public keys found in peers.
// SetPeers is safe for concurrent use.
func (x *Logger) SetPeers(peers []wgcfg.Peer) {
	// Construct a new peer public key log rewriter.
	var replace []string
	for _, peer := range peers {
		old := "peer(" + wireguardGoString(peer.PublicKey) + ")"
		new := peer.PublicKey.ShortString()
		replace = append(replace, old, new)
	}
	r := strings.NewReplacer(replace...)
	x.replacer.Store(r)
}

// wireguardGoString prints p in the same format used by wireguard-go.
func wireguardGoString(k wgcfg.Key) string {
	base64Key := base64.StdEncoding.EncodeToString(k[:])
	abbreviatedKey := "invalid"
	if len(base64Key) == 44 {
		abbreviatedKey = base64Key[0:4] + "…" + base64Key[39:43]
	}
	return abbreviatedKey
}
