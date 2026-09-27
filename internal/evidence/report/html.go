package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/rebaze/rio/internal/delivery"
	"github.com/rebaze/rio/internal/evidence"
)

//go:embed report.html.tmpl
var htmlSource string
var page = template.Must(template.New("report").Funcs(template.FuncMap{"count": func(n any, singular, plural string) string {
	value := fmt.Sprint(n)
	if value == "1" {
		return value + " " + singular
	}
	return value + " " + plural
}, "join": strings.Join, "json": jsonText, "human": func(s string) string { return strings.ReplaceAll(s, "-", " ") }}).Parse(htmlSource))

const HTMLLimit = evidence.FileLimit

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int64
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if int64(len(p)) > b.limit-int64(b.buffer.Len()) {
		return 0, delivery.Fail("size_limit", "maximum report HTML bytes")
	}
	return b.buffer.Write(p)
}
func HTML(m Model) ([]byte, error) { return renderHTML(m, HTMLLimit) }
func renderHTML(m Model, limit int64) ([]byte, error) {
	b := &boundedBuffer{limit: limit}
	if err := page.Execute(io.Writer(b), m); err != nil {
		return nil, err
	}
	return b.buffer.Bytes(), nil
}
