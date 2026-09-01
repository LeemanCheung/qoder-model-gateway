//go:build linux || darwin || freebsd || openbsd || netbsd

package main

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func readBoundedRegularFile(path string, maximum int64, category string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fail(category)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fail(category)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximum {
		return nil, fail(category)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum || int64(len(data)) != info.Size() {
		return nil, fail(category)
	}
	return data, nil
}
