//go:build unix

package rotate

import (
	"errors"
	"os"
	"syscall"
)

func tryLockFile(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return errors.New("lock already held by another process")
	}
	return err
}

func unlockFile(f *os.File) {
	if f != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	}
}
