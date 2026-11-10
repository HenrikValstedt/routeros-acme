//go:build !unix

package main

func lockDataDir(string) error { return nil }
