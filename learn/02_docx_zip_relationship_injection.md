# 02 — OpenXML (.docx) Footer Rewrite

## Understanding OpenXML (ECMA-376)

Modern Microsoft Office documents (`.docx`, `.xlsx`, `.pptx`) are not proprietary binary blobs. They are standard ZIP archives containing a hierarchy of XML files governed by the **Open Packaging Conventions (OPC / ECMA-376)**:

```text
document.docx (ZIP archive)
├── [Content_Types].xml
├── _rels/
│   └── .rels
└── word/
    ├── document.xml
    ├── footer1.xml
    └── _rels/
        ├── document.xml.rels
        └── footer1.xml.rels
```

---

## Why Macro-Based Canaries Fail

Historically, attackers and defenders used VBA macros (`.docm`) to execute beaconing code. However:
- Modern Office suites block VBA macros by default with the "Mark of the Web" (MOTW).
- Endpoint Detection & Response (EDR) software flags macros immediately as suspicious.
- Victims and sophisticated threat actors inspect document extensions and avoid enabling macros.

In contrast, our `.docx` canary requires **zero macros, zero code execution, and zero security warnings**.

---

## The Zero-Click External Relationship Mechanism

Inside the document package, relationships describe how XML elements reference other resources:
- Internal relationships point to embedded files within the ZIP (e.g. `media/image1.png`).
- **External relationships** point to remote URLs on the internet (`TargetMode="External"`).

### 1. Declaring the External Relationship
In `word/_rels/footer1.xml.rels`:
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship 
    Id="rIdCanary" 
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" 
    Target="http://example.com/t/c4f92d8e1a7b" 
    TargetMode="External" />
</Relationships>
```

### 2. Referencing the Relationship in the Footer
In `word/footer1.xml`:
```xml
<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" 
       xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" 
       xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" 
       xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
  <w:p>
    <w:r>
      <w:drawing>
        <wp:inline cx="1" cy="1">
          <a:graphic>
            <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
              <pic:pic>
                <pic:blipFill>
                  <a:blip r:link="rIdCanary" />
                </pic:blipFill>
              </pic:pic>
            </a:graphicData>
          </a:graphic>
        </wp:inline>
      </w:drawing>
    </w:r>
  </w:p>
</w:ftr>
```

---

## Execution Flow on Document Open

1. **Intruder double-clicks `confidential_memo.docx`**.
2. Microsoft Word (or LibreOffice, Office 365, Google Docs importer) parses the Open Packaging hierarchy.
3. Word attempts to render the layout of the default footer.
4. It encounters `<a:blip r:link="rIdCanary" />`.
5. Word initiates an immediate background HTTP GET request to our canary server to render the 1x1 image.
6. The Canary daemon records:
   - Intruder's public IP
   - Word version via `User-Agent: Microsoft Office Word 2019 (16.0.14326) Windows NT 10.0`
   - Exact timestamp
7. The server returns a 43-byte transparent GIF (`pixel.Serve1x1GIF`), Word completes layout rendering silently with zero user prompts.
