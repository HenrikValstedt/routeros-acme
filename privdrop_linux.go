//go:build linux

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// The container starts as root only to read SECRET_KEY_FILE and to give the data
// folder to an unprivileged user; then it switches to that user for good, before
// anything else happens. Users never need to deal with UIDs or file permissions.
// 65532 is the usual "nonroot" ID of minimal images.
const runUID, runGID = 65532, 65532

type privReport struct {
	UID     int
	Fixed   int    // files and folders whose owner was changed
	Warning string // why the process still runs as root
	Partial string // some entries could not be checked or handed over
}

func ownedBy(p string, uid int) bool {
	info, err := os.Lstat(p)
	if err != nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == uid
}

// dropPrivileges switches to runUID:runGID when running as root. With fixOwner, the
// data folder is first handed over to that user (only entries with another owner
// are changed, so this is quick after the first start). If the owner can't be
// changed (e.g. an NFS share with root squash, or no CHOWN capability), the process
// keeps running as root and reports why, instead of failing: an existing setup
// never breaks because of this.
func dropPrivileges(dataDir string, fixOwner bool) privReport {
	if os.Getuid() != 0 {
		return privReport{UID: os.Getuid()}
	}
	rep := privReport{}
	if fixOwner {
		n, err := chownTree(dataDir, runUID, runGID)
		rep.Fixed = n
		if err != nil && !ownedBy(dataDir, runUID) {
			rep.Warning = fmt.Sprintf("cannot hand the data folder to user %d (%v)", runUID, err)
			return rep
		}
		if err != nil {
			// Handed over before (e.g. without the CHOWN capability now): that user
			// can use it, root without capabilities might not.
			rep.Partial = err.Error()
		}
	}
	if err := switchUser(runUID, runGID); err != nil {
		rep.Warning = fmt.Sprintf("cannot switch to user %d (%v)", runUID, err)
		return rep
	}
	rep.UID = os.Getuid()
	return rep
}

func chownTree(root string, uid, gid int) (int, error) {
	n := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) == uid && int(st.Gid) == gid {
			return nil
		}
		if err := os.Lchown(p, uid, gid); err != nil {
			return err
		}
		n++
		return nil
	})
	return n, err
}

// switchUser changes the user of every thread of the process (Go 1.16+). Going from
// root to another user also clears all capabilities, and with no-new-privileges
// (and no setuid programs in the image) nothing can get them back.
func switchUser(uid, gid int) error {
	if err := syscall.Setgroups(nil); err != nil {
		return err
	}
	if err := syscall.Setgid(gid); err != nil {
		return err
	}
	if err := syscall.Setuid(uid); err != nil {
		return err
	}
	if os.Getuid() != uid || os.Geteuid() != uid {
		return errors.New("user did not change")
	}
	return nil
}
