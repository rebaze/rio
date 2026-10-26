package gate

import (
	"strings"
	"testing"
)

func TestSPDXExpression(t *testing.T) {
	accepted := []string{
		"MIT",
		"Apache-2.0",
		"MIT AND Apache-2.0",
		"MIT OR Apache-2.0",
		"MIT and Apache-2.0",
		"MIT or Apache-2.0",
		"Apache-2.0 with LLVM-exception",
		"GPL-2.0+",
		"GPL-2.0-only OR GPL-2.0+",
		"(MIT OR (Apache-2.0 AND (BSD-3-Clause OR Zlib)))",
		"((MIT))",
		"LicenseRef-x",
		"LicenseRef-acme.internal-1",
		"DocumentRef-a:LicenseRef-b",
		"Apache-2.0 WITH LLVM-exception",
		"GPL-2.0-only WITH Classpath-exception-2.0 OR MIT",
		"  MIT  ",
		"(MIT)AND(Apache-2.0)",
	}
	rejected := []string{
		"",
		"   ",
		"MIT AND",
		"(MIT",
		"MIT)",
		"()",
		"MIT OR OR BSD-3-Clause",
		"AND MIT",
		"MIT Apache-2.0",
		"NotALicence-1.0",
		"MIT And Apache-2.0",
		"MIT WITH",
		"MIT WITH NotAnException",
		"(MIT) WITH LLVM-exception",
		"MIT WITH LLVM-exception WITH LLVM-exception",
		"LicenseRef-",
		"LicenseRef-x+",
		"DocumentRef-a:MIT",
		"DocumentRef-:LicenseRef-b",
		"DocumentRef-a:LicenseRef-",
		"MIT++",
		"+",
		"MIT/Apache-2.0",
		"MIT, Apache-2.0",
		"Apache License 2.0",
		// An exception is not a licence, and a licence is not an exception.
		"MIT WITH Apache-2.0",
		"LLVM-exception",
		"LLVM-exception+",
		"MIT OR LLVM-exception",
		"LLVM-exception WITH LLVM-exception",
		"Apache-2.0 WITH LicenseRef-x",
	}
	for _, s := range accepted {
		if !validSPDXExpression(s) {
			t.Errorf("validSPDXExpression(%q) = false, want true", s)
		}
	}
	for _, s := range rejected {
		if validSPDXExpression(s) {
			t.Errorf("validSPDXExpression(%q) = true, want false", s)
		}
	}
}

func TestSPDXExpressionBounds(t *testing.T) {
	nest := func(n int) string {
		return strings.Repeat("(", n) + "MIT" + strings.Repeat(")", n)
	}
	if !validSPDXExpression(nest(64)) {
		t.Error("depth 64 rejected")
	}
	if validSPDXExpression(nest(65)) {
		t.Error("depth 65 accepted")
	}
	if validSPDXExpression(strings.Repeat("MIT OR ", 700) + "MIT") {
		t.Error("expression over 4096 bytes accepted")
	}
	if validSPDXExpression(nest(10_000_000)) {
		t.Error("10 million nested parentheses accepted")
	}
}
