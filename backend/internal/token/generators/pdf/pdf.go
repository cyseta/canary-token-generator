package pdf

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"canary-token-generator/backend/internal/token"
)

type Generator struct{}

func New() *Generator { return &Generator{} }

func (g *Generator) Type() string { return "pdf" }

// escapePDFString escapa los caracteres con significado dentro de una cadena literal PDF.
func escapePDFString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `(`, `\(`, `)`, `\)`, "\r", `\r`, "\n", `\n`)
	return r.Replace(s)
}

// BuildPDF construye el documento calculando en tiempo de ejecucion los offsets de la tabla xref y el
// /Length del stream. Sustituye a la plantilla con offsets fijos y una ventana de URL de 76 bytes, que
// fallaba con dominios largos y declaraba /Length 120 cuando el stream real media 151 bytes
// (qpdf: "expected endstream ... recovering").
func BuildPDF(uri string) []byte {
	stream := "BT\n/F1 18 Tf\n50 720 Td\n(CONFIDENTIAL - INTERNAL SECURITY AUDIT DOCUMENT) Tj\n/F1 12 Tf\n0 -40 Td\n(This document contains proprietary information.) Tj\nET"

	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R /OpenAction << /Type /Action /S /URI /URI (" + escapePDFString(uri) + ") >> >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >> >> >> >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream),
	}

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objs))
	for i, body := range objs {
		offsets[i] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}
	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return buf.Bytes()
}

func (g *Generator) Generate(ctx context.Context, req token.GenerateRequest) (*token.GenerateResult, error) {
	fileName := fmt.Sprintf("confidential_audit_%s.pdf", req.TokenID[:8])
	return &token.GenerateResult{
		Artifact:     BuildPDF(req.TriggerURL),
		ArtifactName: fileName,
		ContentType:  "application/pdf",
		Snippet:      fmt.Sprintf("[PDF Canary Token Document: %s]", fileName),
		Instructions: "Plant this PDF in sensitive folders, backups or shared drives. It contains an OpenAction URI that Adobe Acrobat/Reader may " +
			"follow when the file is opened (current versions usually ask the user to confirm first). Browser viewers (Chrome, Firefox) and most " +
			"preview tools ignore it, so treat this token as LOW reliability and test it with your own readers before relying on it.",
		Metadata: map[string]any{"filename": fileName},
	}, nil
}
