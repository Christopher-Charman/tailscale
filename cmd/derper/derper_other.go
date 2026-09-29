// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package main

import "syscall"

// controlTCPSaveSyn is a no-op on non-Linux platforms, where TCP_SAVE_SYN is
// unavailable. main already logs that --tcp-save-syn is unsupported there.
func controlTCPSaveSyn(network string, c syscall.RawConn) error { return nil }
