package scan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tz0127302-cell/git-supply-guard/internal/model"
)

const maxRead int64 = 2 << 20

var (
	errTooBig     = errors.New("file exceeds scan size limit")
	errNotRegular = errors.New("not a regular file")
)

func readRegular(path string, limit int64) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return nil, errNotRegular
	}
	if st.Size() > limit {
		return nil, errTooBig
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errTooBig
	}
	return data, nil
}

func relSlash(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

func excluded(rel string, patterns []string) bool {
	rel = strings.TrimPrefix(filepath.ToSlash(rel), "./")
	for _, p := range patterns {
		p = strings.Trim(filepath.ToSlash(strings.TrimSpace(p)), "/")
		if p == "" || p == "." {
			continue
		}
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return true
		}
	}
	return false
}

func loc(path string, line int) string {
	if line <= 0 {
		return path
	}
	return fmt.Sprintf("%s:%d", path, line)
}

func dedupeKey(f model.Finding) string {
	location := f.Location
	location = strings.TrimPrefix(location, "tree:")
	if i := strings.LastIndex(location, ":"); i > 0 && allDigits(location[i+1:]) {
		location = location[:i]
	}
	return f.ID + "\n" + location + "\n" + f.Detail
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func insideRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func expandHome(p string) string {
	if p == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return p
		}
		return home
	}
	if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return p
		}
		return filepath.Join(home, p[2:])
	}
	return p
}
