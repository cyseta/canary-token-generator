package docx

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"canary-token-generator/backend/internal/token"
)

type Generator struct{}

func New() *Generator {
	return &Generator{}
}

func (g *Generator) Type() string {
	return "docx"
}

func (g *Generator) Generate(ctx context.Context, req token.GenerateRequest) (*token.GenerateResult, error) {
	docxBytes, err := BuildDecoyDocx(req.TriggerURL, req.Label)
	if err != nil {
		return nil, fmt.Errorf("failed to build docx canary: %w", err)
	}

	fileName := fmt.Sprintf("confidential_memo_%s.docx", req.TokenID[:8])
	instructions := "Plant this Microsoft Word (.docx) document in file shares, desktop folders, or flash drives. " +
		"When opened in MS Word, Word parses the OpenXML footer relationship and fetches the remote canary pixel, " +
		"triggering an alert with the victim's/intruder's IP address and Word client version."

	return &token.GenerateResult{
		Artifact:     docxBytes,
		ArtifactName: fileName,
		ContentType:  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		Snippet:      fmt.Sprintf("[Word Document Canary: %s]", fileName),
		Instructions: instructions,
		Metadata: map[string]any{
			"filename": fileName,
			"target":   req.TriggerURL,
		},
	}, nil
}

// BuildDecoyDocx creates an OpenXML valid .docx archive containing an external image relationship in its footer
func BuildDecoyDocx(triggerURL, title string) ([]byte, error) {
	if title == "" {
		title = "CONFIDENTIAL INTERNAL MEMO"
	}
	escapedURL := xmlEscape(triggerURL)
	escapedTitle := xmlEscape(title)

	contentTypesXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>
</Types>`

	rootRelsXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`

	docRelsXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rIdFooter1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>
</Relationships>`

	docXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <w:body>
    <w:p>
      <w:pPr><w:jc w:val="center"/></w:pPr>
      <w:r>
        <w:rPr><w:b/><w:sz w:val="36"/></w:rPr>
        <w:t>%s</w:t>
      </w:r>
    </w:p>
    <w:p>
      <w:r>
        <w:t>Notice: This document contains restricted enterprise data. Unauthorized access or reproduction is strictly logged and audited.</w:t>
      </w:r>
    </w:p>
    <w:sectPr>
      <w:footerReference w:type="default" r:id="rIdFooter1"/>
    </w:sectPr>
  </w:body>
</w:document>`, escapedTitle)

	footerRelsXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="%s" TargetMode="External"/>
</Relationships>`, escapedURL)

	footerXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
  <w:p>
    <w:r>
      <w:drawing>
        <wp:inline distT="0" distB="0" distL="0" distR="0">
          <wp:extent cx="1" cy="1"/>
          <wp:docPr id="1" name="Picture 1"/>
          <a:graphic>
            <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
              <pic:pic>
                <pic:nvPicPr>
                  <pic:cNvPr id="0" name="image1.png"/>
                  <pic:cNvPicPr/>
                </pic:nvPicPr>
                <pic:blipFill>
                  <a:blip r:link="rId1"/>
                  <a:stretch><a:fillRect/></a:stretch>
                </pic:blipFill>
                <pic:spPr>
                  <a:xfrm><a:off x="0" y="0"/><a:ext cx="1" cy="1"/></a:xfrm>
                  <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
                </pic:spPr>
              </pic:pic>
            </a:graphicData>
          </a:graphic>
        </wp:inline>
      </w:drawing>
    </w:r>
  </w:p>
</w:ftr>`

	// Orden FIJO: [Content_Types].xml primero (algunos lectores y detectores de tipo, p.ej. libmagic,
	// lo esperan asi). Iterar un map hacia que el orden y los bytes variaran en cada descarga.
	files := []struct{ name, content string }{
		{"[Content_Types].xml", contentTypesXML},
		{"_rels/.rels", rootRelsXML},
		{"word/document.xml", docXML},
		{"word/_rels/document.xml.rels", docRelsXML},
		{"word/footer1.xml", footerXML},
		{"word/_rels/footer1.xml.rels", footerRelsXML},
	}

	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)
	stamp := time.Date(2025, 1, 15, 9, 0, 0, 0, time.UTC) // fecha fija: salida determinista y sin el sello 1979 de una fecha cero

	for _, f := range files {
		w, err := zipWriter.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Deflate, Modified: stamp})
		if err != nil {
			return nil, err
		}
		if _, err := io.WriteString(w, strings.TrimSpace(f.content)); err != nil {
			return nil, err
		}
	}
	if err := zipWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// xmlEscape escapa texto/atributos XML y sustituye los caracteres no validos en XML 1.0 (p.ej. \x00), que
// harian que Word declarase el documento corrupto cuando la etiqueta contiene caracteres de control.
func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
