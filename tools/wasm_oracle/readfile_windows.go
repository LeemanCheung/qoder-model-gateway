//go:build windows

package main

import (
	"io"
	"os"
)

func readBoundedRegularFile(path string, maximum int64, category string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() > maximum {
		return nil, fail(category)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fail(category)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() > maximum {
		return nil, fail(category)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum || int64(len(data)) != after.Size() {
		return nil, fail(category)
	}
	return data, nil
}
