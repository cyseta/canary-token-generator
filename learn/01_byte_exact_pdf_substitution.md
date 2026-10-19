> **Update:** the byte-exact 76-byte placeholder technique described here was replaced by `pdf.BuildPDF`, which computes the xref offsets and `/Length` at build time. The old template declared `/Length 120` for a 151-byte stream (qpdf reported damage) and failed for BASE_URLs longer than 48 characters. Kept for historical interest.

# 01 — Byte-Exact PDF Substitution

## The Problem: PDF Cross-Reference (xref) Offsets

A Portable Document Format (PDF) file is not just a stream of plain text. At the end of every valid PDF file is an **xref (cross-reference) table**:

```text
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000202 00000 n 
0000000265 00000 n 
0000000501 00000 n 
trailer
<<
  /Size 5
  /Root 1 0 R
>>
startxref
704
%%EOF
```

Every entry in the table specifies the **exact byte offset from the beginning of the file** where each object (`1 0 obj`, `2 0 obj`, etc.) resides.

### The Pitfall of Dynamic PDF Generation
If you load a template PDF and perform a naive string substitution:
```go
// NAIVE: BREAKS THE PDF!
template = strings.Replace(template, "{{URL}}", dynamicURL, 1)
```
If `{{URL}}` is 7 characters and `dynamicURL` is 38 characters:
1. Every subsequent object in the file shifts by `+31` bytes.
2. The xref table now points to invalid offsets.
3. The `startxref` offset pointing to the xref table itself is now wrong.
4. Compliant PDF readers (Adobe Acrobat, Foxit, Chrome, macOS Preview) will either crash, declare the document corrupt, or enter silent repair mode—which disables `/OpenAction` execution!

---

## The Solution: The 76-Byte Window

Instead of rebuilding the PDF parser and recalculating xref tables on the fly for every HTTP request, we use **byte-exact placeholder substitution**.

1. In the pre-compiled template, we define a fixed-length placeholder string:
```text
http://CANARY_PLACEHOLDER_STRING_FOR_BYTE_EXACT_REPLACEMENT_EXACTLY_76_BYTES
```
*(Exact length: 76 bytes)*

2. When a user requests a PDF canary, we compute their target trigger URL:
```text
http://example.com/t/c4f92d8e1a7b
```
*(Length: 35 bytes)*

3. We pad the URL to **exactly 76 bytes** using an HTTP fragment identifier (`#`):
```text
http://example.com/t/c4f92d8e1a7b#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

### Why Fragment `#` Padding Works
- According to **RFC 3986**, the fragment identifier (`#...`) is evaluated purely on the client side and is **never sent across the wire** in the HTTP request line.
- The web server receives the exact request: `GET /t/c4f92d8e1a7b HTTP/1.1`.
- The PDF reader handles the full 76-byte string cleanly.
- The byte offset of every object and the `startxref` position remain **100% byte-accurate**.

---

## PDF OpenAction Trigger Specification

Inside the Catalog object (`1 0 obj`), an `/OpenAction` dictionary is declared:

```pdf
1 0 obj
<<
  /Type /Catalog
  /Pages 2 0 R
  /OpenAction <<
    /Type /Action
    /S /URI
    /URI (http://CANARY_PLACEHOLDER_STRING_FOR_BYTE_EXACT_REPLACEMENT_EXACTLY_76_BYTES)
  >>
>>
endobj
```

When a victim or attacker opens the PDF:
1. The PDF reader initializes the document catalog.
2. It detects the `/OpenAction` directive.
3. It dispatches a background HTTP GET request to the target URI.
4. The Canary daemon logs the intruder's IP, location, and reader version.
