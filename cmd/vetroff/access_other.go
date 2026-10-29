//go:build !unix

package main

import "github.com/SawaMEN/VetroffProxy/internal/access"

func watchAccess(*access.Controller, string, bool) func() { return func() {} }
