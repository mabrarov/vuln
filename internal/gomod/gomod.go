// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gomod

import (
	"os"
	"os/exec"
	"strings"
)

func Path(dir string) (string, bool) {
	cmd := exec.Command("go", "env", "GOMOD")
	cmd.Dir = dir
	out, err := cmd.Output()
	output := strings.TrimSpace(string(out))
	// If module-aware mode is enabled, but there is no go.mod, GOMOD will be os.DevNull
	// If module-aware mode is disabled, GOMOD will be the empty string.
	return output, err == nil && !(output == os.DevNull || output == "")
}
