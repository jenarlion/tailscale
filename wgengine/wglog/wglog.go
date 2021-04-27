// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wglog contains logging helpers for wireguard-go.
package wglog

import (
	"encoding/base64"
	"strings"
	"sync/atomic"

	"github.com/tailscale/wireguard-go/device"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/wgcfg"
)

// A Logger is a wireguard-go log wrapper that cleans up and rewrites log lines.
// It can be modified at run time to adjust to new wireguard-go configurations.
type Logger struct {
	DeviceLogger *device.Logger
	replace      atomic.Value // of map[string]string
}

// NewLogger creates a new logger for use with wireguard-go.
// This logger silences repetitive/unhelpful noisy log lines
// and rewrites peer keys from wireguard-go into Tailscale format.
func NewLogger(logf logger.Logf) *Logger {
	ret := new(Logger)
	wrapper := func(format string, args ...interface{}) {
		if strings.Contains(format, "Routine:") && !strings.Contains(format, "receive incoming") {
			// wireguard-go logs as it starts and stops routines.
			// Drop those; there are a lot of them, and they're just noise.
			return
		}
		if strings.Contains(format, "Failed to send data packet") {
			// Drop. See https://github.com/tailscale/tailscale/issues/1239.
			return
		}
		if strings.Contains(format, "Interface up requested") || strings.Contains(format, "Interface down requested") {
			// Drop. Logs 1/s constantly while the tun device is open.
			// See https://github.com/tailscale/tailscale/issues/1388.
			return
		}
		replace, _ := ret.replace.Load().(map[string]string)
		if replace == nil {
			// No replacements specified; log as originally planned.
			logf(format, args...)
			return
		}
		// Do the replacements.
		for i, arg := range args {
			peer, ok := arg.(*device.Peer)
			if !ok {
				continue
			}
			wgStr := peer.String()
			tsStr, ok := replace[wgStr]
			if !ok {
				continue
			}
			args[i] = tsStr
		}
		logf(format, args...)
	}
	ret.DeviceLogger = &device.Logger{
		Verbosef: logger.WithPrefix(wrapper, "[v2] "),
		Errorf:   wrapper,
	}
	return ret
}

// SetPeers adjusts x to rewrite the peer public keys found in peers.
// SetPeers is safe for concurrent use.
func (x *Logger) SetPeers(peers []wgcfg.Peer) {
	// Construct a new peer public key log rewriter.
	replace := make(map[string]string)
	for _, peer := range peers {
		old := "peer(" + wireguardGoString(peer.PublicKey) + ")"
		new := peer.PublicKey.ShortString()
		replace[old] = new
	}
	x.replace.Store(replace)
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
