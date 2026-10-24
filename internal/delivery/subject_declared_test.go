package delivery

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rebaze/rio/internal/buildcontext"
	"github.com/rebaze/rio/internal/index"
	"github.com/rebaze/rio/internal/sbom"
)

func TestCheckSubjectDeclaredFailsClosedOnUnreadableIdentity(t *testing.T) {
	a := index.Artifact{ID: "app", Context: &sbom.ContextRecord{Effective: buildcontext.Artifact{
		Distributions: []buildcontext.Distribution{{Name: "a", SHA256: strings.Repeat("ab", 32)}},
	}}}
	d := Description{Type: "oci", Identity: json.RawMessage(`"not an object"`)}
	err := checkSubjectDeclared(a, d)
	if err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("err = %v, want unreadable identity refusal", err)
	}
}
