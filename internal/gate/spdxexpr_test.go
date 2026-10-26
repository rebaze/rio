package gate

import "testing"

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
