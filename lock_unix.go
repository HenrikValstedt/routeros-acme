//go:build unix

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// dataLock stays open for the life of the process; closing it releases the lock.
var dataLock *os.File

// lockDataDir takes an exclusive lock on the data directory, so two processes
// (a second container, or a -reset-2fa run) never write config.json at the same time.
func lockDataDir(dir string) error {
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return errors.New("another RouterOS ACME process is using this data directory")
	}
	dataLock = f
	return nil
}
