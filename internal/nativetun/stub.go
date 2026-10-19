//go:build !linux

package nativetun

import (
 "context"
 "errors"
)

type Options struct{ Name string; MTU uint32; SOCKS string }
type Runner struct{}
func (r *Runner) Close(){}
func Validate(Options) error{return errors.New("native TUN currently supports Linux only")}
func Start(context.Context,Options)(*Runner,error){return nil,Validate(Options{})}
