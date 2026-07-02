// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sarif

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/govulncheck"
)

func scanLevel(f *govulncheck.Finding) string {
	fr := f.Trace[0]
	if fr.Function != "" {
		return "symbol"
	}
	if fr.Package != "" {
		return "package"
	}
	return "module"
}

func newTestHandler() *handler {
	h := NewHandler(nil, nil)
	h.cfg = &govulncheck.Config{}
	return h
}

func TestLoadGomodValid(t *testing.T) {
	moduleLines, err := LoadGomod(filepath.FromSlash("testdata/modules/valid/subdir"))
	if err != nil {
		t.Fatalf("error loading go.mod: %v", err)
	}

	want := map[string]int{
		internal.GoStdModulePath:           3,
		"github.com/tidwall/gjson@v1.6.5":  8,
		"golang.org/x/text@v0.3.0":         11,
		"github.com/tidwall/match@v1.1.0":  15,
		"github.com/tidwall/pretty@v1.2.0": 16,
	}
	got := make(map[string]int)
	for module, line := range moduleLines {
		got[module] = line.Start.Line
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-want;got+): %s", diff)
	}
}

func TestLoadGomodInvalid(t *testing.T) {
	moduleLines, err := LoadGomod(filepath.FromSlash("testdata/modules/invalid"))
	if err == nil {
		t.Error("expected error in case of invalid go.mod")
	}
	if moduleLines != nil {
		t.Errorf("expected nil in case of error, got: %+v", moduleLines)
	}
}

func TestHandlerSymbol(t *testing.T) {
	fs := `
{
  "finding": {
    "osv": "GO-2021-0054",
    "trace": [
      {
        "module": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0265",
    "trace": [
      {
        "module": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2020-0015",
    "trace": [
      {
        "module": "golang.org/x/text"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0054",
    "trace": [
      {
        "module": "github.com/tidwall/gjson",
        "package": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0265",
    "trace": [
      {
        "module": "github.com/tidwall/gjson",
        "package": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0265",
    "trace": [
      {
        "module": "github.com/tidwall/gjson",
        "package": "github.com/tidwall/gjson",
        "function": "Get",
        "receiver": "Result"
      },
      {
        "module": "golang.org/vuln",
        "package": "golang.org/vuln",
        "function": "main"
      }
    ]
  }
}`

	h := newTestHandler()
	if err := govulncheck.HandleJSON(strings.NewReader(fs), h); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"GO-2021-0265": "symbol",
		"GO-2021-0054": "package",
		"GO-2020-0015": "module",
	}
	got := make(map[string]string)
	for osv, fs := range h.findings {
		got[osv] = scanLevel(fs[0])
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-want;got+): %s", diff)
	}
}

func TestHandlerPackage(t *testing.T) {
	fs := `
{
  "finding": {
    "osv": "GO-2021-0054",
    "trace": [
      {
        "module": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0265",
    "trace": [
      {
        "module": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2020-0015",
    "trace": [
      {
        "module": "golang.org/x/text"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0054",
    "trace": [
      {
        "module": "github.com/tidwall/gjson",
        "package": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0265",
    "trace": [
      {
        "module": "github.com/tidwall/gjson",
        "package": "github.com/tidwall/gjson"
      }
    ]
  }
}`

	h := newTestHandler()
	if err := govulncheck.HandleJSON(strings.NewReader(fs), h); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"GO-2021-0265": "package",
		"GO-2021-0054": "package",
		"GO-2020-0015": "module",
	}
	got := make(map[string]string)
	for osv, fs := range h.findings {
		got[osv] = scanLevel(fs[0])
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-want;got+): %s", diff)
	}
}

func TestHandlerModule(t *testing.T) {
	fs := `
{
  "finding": {
    "osv": "GO-2021-0054",
    "trace": [
      {
        "module": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2021-0265",
    "trace": [
      {
        "module": "github.com/tidwall/gjson"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2020-0015",
    "trace": [
      {
        "module": "golang.org/x/text"
      }
    ]
  }
}`

	h := newTestHandler()
	if err := govulncheck.HandleJSON(strings.NewReader(fs), h); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"GO-2021-0265": "module",
		"GO-2021-0054": "module",
		"GO-2020-0015": "module",
	}
	got := make(map[string]string)
	for osv, fs := range h.findings {
		got[osv] = scanLevel(fs[0])
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-want;got+): %s", diff)
	}
}

func TestMoreSpecific(t *testing.T) {
	frame := func(m, p, f string) *govulncheck.Frame {
		return &govulncheck.Frame{
			Module:   m,
			Package:  p,
			Function: f,
		}
	}

	for _, tc := range []struct {
		name   string
		want   int
		trace1 []*govulncheck.Frame
		trace2 []*govulncheck.Frame
	}{
		{"sym-vs-sym", 0,
			[]*govulncheck.Frame{
				frame("m1", "p1", "v1"), frame("m1", "p1", "f2")},
			[]*govulncheck.Frame{
				frame("m1", "p1", "v2"), frame("m1", "p1", "f1"), frame("m2", "p2", "f2")},
		},
		{"sym-vs-pkg", -1,
			[]*govulncheck.Frame{
				frame("m1", "p1", "v1"), frame("m1", "p1", "f2")},
			[]*govulncheck.Frame{
				frame("m1", "p1", "")},
		},
		{"pkg-vs-sym", 1,
			[]*govulncheck.Frame{
				frame("m1", "p1", "")},
			[]*govulncheck.Frame{
				frame("m1", "p1", "v1"), frame("m2", "p2", "v2")},
		},
		{"pkg-vs-mod", -1,
			[]*govulncheck.Frame{
				frame("m1", "p1", "")},
			[]*govulncheck.Frame{
				frame("m1", "", "")},
		},
		{"mod-vs-sym", 1,
			[]*govulncheck.Frame{
				frame("m1", "", "")},
			[]*govulncheck.Frame{
				frame("m1", "p1", "v2"), frame("m1", "p1", "f1")},
		},
		{"mod-vs-mod", 0,
			[]*govulncheck.Frame{
				frame("m1", "", "")},
			[]*govulncheck.Frame{
				frame("m2", "", "")},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f1 := &govulncheck.Finding{Trace: tc.trace1}
			f2 := &govulncheck.Finding{Trace: tc.trace2}
			if got := moreSpecific(f1, f2); got != tc.want {
				t.Errorf("want %d; got %d", tc.want, got)
			}
		})
	}
}

func TestResultMessage(t *testing.T) {
	config := func(l govulncheck.ScanLevel) *govulncheck.Config {
		return &govulncheck.Config{ScanLevel: l}
	}

	finding := func(m, p, f string) *govulncheck.Finding {
		return &govulncheck.Finding{
			Trace: []*govulncheck.Frame{
				{Module: m, Package: p, Function: f},
			},
		}
	}

	for _, tc := range []struct {
		findings []*govulncheck.Finding
		level    govulncheck.ScanLevel
		want     string
	}{
		{[]*govulncheck.Finding{finding("m", "p", "f1"), finding("m", "p", "f2")}, govulncheck.ScanLevelSymbol,
			"Your code calls vulnerable functions in 1 package (p)."},
		{[]*govulncheck.Finding{finding("m", "p", "")}, govulncheck.ScanLevelPackage,
			"Your code imports 1 vulnerable package (p). Run the call-level analysis to understand whether your code actually calls the vulnerabilities."},
		{[]*govulncheck.Finding{finding("m", "p1", ""), finding("m", "p2", ""), finding("m", "p3", "")}, govulncheck.ScanLevelSymbol,
			"Your code imports 3 vulnerable packages (p1, p2, and p3), but doesn’t appear to call any of the vulnerable symbols."},
		{[]*govulncheck.Finding{finding("m1", "", ""), finding("m2", "", "")}, govulncheck.ScanLevelModule,
			"Your code depends on 2 vulnerable modules (m1 and m2). Run the call-level analysis to understand whether your code actually calls the vulnerabilities."},
		{[]*govulncheck.Finding{finding("m1", "", ""), finding("m2", "", "")}, govulncheck.ScanLevelPackage,
			"Your code depends on 2 vulnerable modules (m1 and m2), but doesn't appear to import any of the vulnerable symbols."},
		{[]*govulncheck.Finding{finding("m1", "", ""), finding("m2", "", "")}, govulncheck.ScanLevelSymbol,
			"Your code depends on 2 vulnerable modules (m1 and m2), but doesn't appear to call any of the vulnerable symbols."},
	} {
		got := resultMessage(tc.findings, config(tc.level))
		if tc.want != got {
			t.Errorf("want %s; got %s", tc.want, got)
		}
	}
}
