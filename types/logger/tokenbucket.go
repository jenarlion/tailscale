// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logger

import (
	"time"
)

type tokenBucket struct {
	remaining int
	max       int
	tick      time.Duration
	t         time.Time
}

func newTokenBucket(tick time.Duration, max int, now time.Time) *tokenBucket {
	return &tokenBucket{max, max, tick, now}
}

func (tb *tokenBucket) Get() bool {
	if tb.remaining > 0 {
		tb.remaining--
		return true
	}
	return false
}

func (tb *tokenBucket) Refund(n int) {
	b := tb.remaining + n
	if b > tb.max {
		tb.remaining = tb.max
	} else {
		tb.remaining = b
	}
}

func (tb *tokenBucket) AdvanceTo(t time.Time) {
	diff := t.Sub(tb.t)

	// only use up whole ticks. The remainder will be used up
	// next time.
	ticks := int(diff / tb.tick)
	tb.t = tb.t.Add(time.Duration(ticks) * tb.tick)

	tb.Refund(ticks)
}
