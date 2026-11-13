//go:build !linux

package main

import "os"

type privReport struct {
	UID     int
	Fixed   int
	Warning string
	Partial string
}

func dropPrivileges(string, bool) privReport { return privReport{UID: os.Getuid()} }
