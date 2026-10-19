//go:build !unix

package main

import "github.com/SawaMEN/FoxTunnel/internal/access"

func watchAccess(*access.Controller, string, bool) func() { return func() {} }
