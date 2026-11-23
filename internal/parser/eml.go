package parser

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"unicode/utf8"

	"github.com/gorkemguler/zarf/internal/model"
)

const maxMIMEDepth = 12

// ParsedPart represents a decoded leaf MIME entity.
type ParsedPart struct {
	ContentType        string
	MediaType          string
	MediaParams        map[string]string
	ContentDisposition string
	DispParams         map[string]string
	ContentID          string
	TransferEncoding   string
	Filename           string
	IsAttachment       bool
	IsInline           bool
	Body               []byte
	Text               string
}

// ParsedEmail holds the lossless raw sections and structured MIME tree of an .eml file.
type ParsedEmail struct {
	Filename   string
	Raw        []byte
	RawHeaders []byte
	RawBody    []byte
	Evidence   model.EvidenceManifest
	Headers    []model.HeaderKV
	HeaderMap  textproto.MIMEHeader
	PlainTexts []string
	HTMLBodies []string
	Parts      []ParsedPart
	NestedEMLs [][]byte
}

// ParseEML parses a raw RFC 5322 / MIME email completely offline.
func ParseEML(filename string, raw []byte) (*ParsedEmail, error) {
	ev := computeEvidence(filename, raw)

	// Strip UTF-8 BOM only for parsing while keeping original Raw for hashing.
	work := raw
	if bytes.HasPrefix(work, []byte{0xEF, 0xBB, 0xBF}) {
		work = work[3:]
	}

	rawHdr, rawBody := splitHeaderBody(work)
	ev.HeaderSize = len(rawHdr)
	ev.BodySize = len(rawBody)

	ordered, hdrMap := parseOrderedHeaders(rawHdr)

	pe := &ParsedEmail{
		Filename:   filename,
		Raw:        raw,
		RawHeaders: rawHdr,
		RawBody:    rawBody,
		Evidence:   ev,
		Headers:    ordered,
		HeaderMap:  hdrMap,
	}

	ct := hdrMap.Get("Content-Type")
	if ct == "" {
		ct = "text/plain; charset=utf-8"
	}
	cte := hdrMap.Get("Content-Transfer-Encoding")
	cd := hdrMap.Get("Content-Disposition")
	cid := hdrMap.Get("Content-Id")

	pe.walkEntity(ct, cte, cd, cid, rawBody, 0)
	return pe, nil
}

func computeEvidence(filename string, raw []byte) model.EvidenceManifest {
	h256 := sha256.Sum256(raw)
	h1 := sha1.Sum(raw)
	hm := md5.Sum(raw)
	lines := bytes.Count(raw, []byte{'\n'})
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		lines++
	}
	return model.EvidenceManifest{
		Filename:  filename,
		SizeBytes: int64(len(raw)),
		SHA256:    hex.EncodeToString(h256[:]),
		SHA1:      hex.EncodeToString(h1[:]),
		MD5:       hex.EncodeToString(hm[:]),
		LineCount: lines,
	}
}

func splitHeaderBody(data []byte) ([]byte, []byte) {
	// RFC 5322 separates headers and body by an empty line (CRLFCRLF or LFLF).
	idxCRLF := bytes.Index(data, []byte("\r\n\r\n"))
	idxLF := bytes.Index(data, []byte("\n\n"))

	switch {
	case idxCRLF >= 0 && (idxLF < 0 || idxCRLF < idxLF):
		return data[:idxCRLF], data[idxCRLF+4:]
	case idxLF >= 0:
		return data[:idxLF], data[idxLF+2:]
	default:
		// Edge case: headers only, no body
		return data, nil
	}
}

func parseOrderedHeaders(rawHdr []byte) ([]model.HeaderKV, textproto.MIMEHeader) {
	hdrMap := make(textproto.MIMEHeader)
	var ordered []model.HeaderKV

	normalized := bytes.ReplaceAll(rawHdr, []byte("\r\n"), []byte("\n"))
	lines := bytes.Split(normalized, []byte("\n"))

	var curName string
	var curVal strings.Builder

	flush := func() {
		if curName == "" {
			return
		}
		val := strings.TrimSpace(curVal.String())
		ordered = append(ordered, model.HeaderKV{Name: curName, Value: val})
		hdrMap.Add(curName, val)
		curName = ""
		curVal.Reset()
	}

	for _, lineBytes := range lines {
		line := string(lineBytes)
		if len(line) == 0 {
			continue
		}
		// Continuation / folded header line
		if line[0] == ' ' || line[0] == '\t' {
			if curName != "" {
				curVal.WriteByte(' ')
				curVal.WriteString(strings.TrimSpace(line))
			}
			continue
		}
		// Skip mbox "From " separator if present at very start
		if len(ordered) == 0 && curName == "" && strings.HasPrefix(line, "From ") {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		flush()
		curName = strings.TrimSpace(line[:colon])
		curVal.WriteString(strings.TrimSpace(line[colon+1:]))
	}
	flush()

	return ordered, hdrMap
}

func (pe *ParsedEmail) walkEntity(contentType, transferEncoding, contentDisposition, contentID string, body []byte, depth int) {
	if depth > maxMIMEDepth {
		return
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		// Fallback on malformed Content-Type
		base := strings.TrimSpace(strings.Split(contentType, ";")[0])
		mediaType = strings.ToLower(base)
		if mediaType == "" {
			mediaType = "text/plain"
		}
		params = map[string]string{}
	}
	mediaType = strings.ToLower(mediaType)

	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			// Best-effort boundary rescue
			boundary = extractBoundaryFallback(contentType)
		}
		if boundary != "" {
			mr := multipart.NewReader(bytes.NewReader(body), boundary)
			for {
				p, err := mr.NextRawPart()
				if err != nil {
					break
				}
				partBody, _ := io.ReadAll(io.LimitReader(p, 50*1024*1024))
				pCT := p.Header.Get("Content-Type")
				if pCT == "" {
					if mediaType == "multipart/digest" {
						pCT = "message/rfc822"
					} else {
						pCT = "text/plain; charset=utf-8"
					}
				}
				pCTE := p.Header.Get("Content-Transfer-Encoding")
				pCD := p.Header.Get("Content-Disposition")
				pCID := p.Header.Get("Content-Id")
				pe.walkEntity(pCT, pCTE, pCD, pCID, partBody, depth+1)
				_ = p.Close()
			}
			return
		}
	}

	decoded := decodeTransferEncoding(transferEncoding, body)

	if mediaType == "message/rfc822" {
		if len(decoded) > 0 {
			pe.NestedEMLs = append(pe.NestedEMLs, decoded)
		}
	}

	dispType, dispParams, _ := mime.ParseMediaType(contentDisposition)
	dispType = strings.ToLower(dispType)

	filename := ""
	if fn, ok := dispParams["filename"]; ok && fn != "" {
		filename = DecodeRFC2047(fn)
	} else if name, ok := params["name"]; ok && name != "" {
		filename = DecodeRFC2047(name)
	}

	isInline := dispType == "inline" || (contentID != "" && dispType != "attachment")
	isAttachment := dispType == "attachment" || filename != "" ||
		(!strings.HasPrefix(mediaType, "text/") && mediaType != "multipart/alternative")

	// Don't treat standard body text/plain or text/html without filename as attachments
	if (mediaType == "text/plain" || mediaType == "text/html") && filename == "" && dispType != "attachment" {
		isAttachment = false
	}

	charset := params["charset"]
	text := ""
	if strings.HasPrefix(mediaType, "text/") {
		text = DecodeCharset(decoded, charset)
	}

	part := ParsedPart{
		ContentType:        contentType,
		MediaType:          mediaType,
		MediaParams:        params,
		ContentDisposition: dispType,
		DispParams:         dispParams,
		ContentID:          strings.Trim(contentID, "<> "),
		TransferEncoding:   strings.ToLower(strings.TrimSpace(transferEncoding)),
		Filename:           filename,
		IsAttachment:       isAttachment,
		IsInline:           isInline,
		Body:               decoded,
		Text:               text,
	}
	pe.Parts = append(pe.Parts, part)

	if !isAttachment {
		if mediaType == "text/plain" {
			pe.PlainTexts = append(pe.PlainTexts, text)
		} else if mediaType == "text/html" {
			pe.HTMLBodies = append(pe.HTMLBodies, text)
		}
	}
}

func extractBoundaryFallback(ct string) string {
	lower := strings.ToLower(ct)
	idx := strings.Index(lower, "boundary=")
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(ct[idx+len("boundary="):])
	if len(rest) == 0 {
		return ""
	}
	if rest[0] == '"' {
		if end := strings.IndexByte(rest[1:], '"'); end >= 0 {
			return rest[1 : end+1]
		}
		return strings.Trim(rest, "\"")
	}
	if semi := strings.IndexByte(rest, ';'); semi >= 0 {
		return strings.TrimSpace(rest[:semi])
	}
	return strings.TrimSpace(rest)
}

func decodeTransferEncoding(enc string, data []byte) []byte {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "base64":
		return decodeBase64Lenient(data)
	case "quoted-printable":
		r := quotedprintable.NewReader(bytes.NewReader(data))
		out, err := io.ReadAll(r)
		if err != nil && len(out) == 0 {
			return data
		}
		return out
	default:
		return data
	}
}

func decodeBase64Lenient(data []byte) []byte {
	// Strip whitespace and control characters often inserted by MTAs
	cleaned := make([]byte, 0, len(data))
	for _, b := range data {
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
			(b >= '0' && b <= '9') || b == '+' || b == '/' || b == '=' || b == '-' || b == '_' {
			cleaned = append(cleaned, b)
		}
	}
	if len(cleaned) == 0 {
		return nil
	}
	// Try standard first, then RawStdEncoding if padding is missing
	if out, err := base64.StdEncoding.DecodeString(string(cleaned)); err == nil {
		return out
	}
	trimmed := strings.TrimRight(string(cleaned), "=")
	if out, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil {
		return out
	}
	if out, err := base64.RawURLEncoding.DecodeString(trimmed); err == nil {
		return out
	}
	return data
}

// DecodeRFC2047 decodes MIME RFC 2047 header encoded words (=?charset?B/Q?...?=)
// including UTF-8, ISO-8859-1, ISO-8859-9 (Turkish), Windows-1252, and Windows-1254.
func DecodeRFC2047(s string) string {
	if !strings.Contains(s, "=?") {
		return s
	}
	dec := &mime.WordDecoder{
		CharsetReader: func(charset string, input io.Reader) (io.Reader, error) {
			raw, err := io.ReadAll(input)
			if err != nil {
				return nil, err
			}
			return strings.NewReader(DecodeCharset(raw, charset)), nil
		},
	}
	out, err := dec.DecodeHeader(s)
	if err != nil {
		return s
	}
	return out
}

// DecodeCharset decodes common email charsets to UTF-8 with zero external dependencies.
func DecodeCharset(b []byte, charset string) string {
	cs := strings.ToLower(strings.TrimSpace(charset))
	cs = strings.Trim(cs, "\"'")
	switch cs {
	case "", "utf-8", "utf8", "us-ascii", "ascii":
		if utf8.Valid(b) {
			return string(b)
		}
		return decodeWindows1252(b)
	case "iso-8859-1", "latin1", "latin-1":
		runes := make([]rune, len(b))
		for i, c := range b {
			runes[i] = rune(c)
		}
		return string(runes)
	case "windows-1252", "cp1252":
		return decodeWindows1252(b)
	case "iso-8859-9", "latin5", "latin-5":
		return decodeISO88599(b)
	case "windows-1254", "cp1254":
		return decodeWindows1254(b)
	default:
		if utf8.Valid(b) {
			return string(b)
		}
		return decodeWindows1252(b)
	}
}

var cp1252Extra = map[byte]rune{
	0x80: 0x20AC, 0x82: 0x201A, 0x83: 0x0192, 0x84: 0x201E, 0x85: 0x2026,
	0x86: 0x2020, 0x87: 0x2021, 0x88: 0x02C6, 0x89: 0x2030, 0x8A: 0x0160,
	0x8B: 0x2039, 0x8C: 0x0152, 0x8E: 0x017D, 0x91: 0x2018, 0x92: 0x2019,
	0x93: 0x201C, 0x94: 0x201D, 0x95: 0x2022, 0x96: 0x2013, 0x97: 0x2014,
	0x98: 0x02DC, 0x99: 0x2122, 0x9A: 0x0161, 0x9B: 0x203A, 0x9C: 0x0153,
	0x9E: 0x017E, 0x9F: 0x0178,
}

func decodeWindows1252(b []byte) string {
	runes := make([]rune, len(b))
	for i, c := range b {
		if r, ok := cp1252Extra[c]; ok {
			runes[i] = r
		} else {
			runes[i] = rune(c)
		}
	}
	return string(runes)
}

var iso88599Map = map[byte]rune{
	0xD0: 'Ğ', 0xDD: 'İ', 0xDE: 'Ş',
	0xF0: 'ğ', 0xFD: 'ı', 0xFE: 'ş',
}

func decodeISO88599(b []byte) string {
	runes := make([]rune, len(b))
	for i, c := range b {
		if r, ok := iso88599Map[c]; ok {
			runes[i] = r
		} else {
			runes[i] = rune(c)
		}
	}
	return string(runes)
}

func decodeWindows1254(b []byte) string {
	runes := make([]rune, len(b))
	for i, c := range b {
		if r, ok := iso88599Map[c]; ok {
			runes[i] = r
		} else if r, ok := cp1252Extra[c]; ok {
			runes[i] = r
		} else {
			runes[i] = rune(c)
		}
	}
	return string(runes)
}

// ParseAddress parses a single RFC 5322 email address safely.
func ParseAddress(raw string) *model.Address {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	decoded := DecodeRFC2047(raw)
	if addr, err := mail.ParseAddress(decoded); err == nil {
		return toModelAddress(addr.Name, addr.Address, raw)
	}
	// Fallback: extract angle-bracketed email or bare email
	if l := strings.LastIndexByte(decoded, '<'); l >= 0 {
		if r := strings.IndexByte(decoded[l:], '>'); r > 1 {
			email := strings.TrimSpace(decoded[l+1 : l+r])
			name := strings.Trim(strings.TrimSpace(decoded[:l]), "\"'")
			return toModelAddress(name, email, raw)
		}
	}
	if strings.Contains(decoded, "@") {
		return toModelAddress("", strings.Trim(decoded, "<>\"' "), raw)
	}
	return &model.Address{DisplayName: decoded, Raw: raw}
}

// ParseAddressList parses a comma-separated list of RFC 5322 addresses safely.
func ParseAddressList(raw string) []model.Address {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	decoded := DecodeRFC2047(raw)
	if list, err := mail.ParseAddressList(decoded); err == nil {
		out := make([]model.Address, 0, len(list))
		for _, a := range list {
			out = append(out, *toModelAddress(a.Name, a.Address, raw))
		}
		return out
	}
	// Fallback split by comma
	parts := strings.Split(decoded, ",")
	var out []model.Address
	for _, p := range parts {
		if a := ParseAddress(p); a != nil && (a.Address != "" || a.DisplayName != "") {
			out = append(out, *a)
		}
	}
	return out
}

func toModelAddress(name, addr, raw string) *model.Address {
	addr = strings.TrimSpace(addr)
	local, domain := "", ""
	if at := strings.LastIndexByte(addr, '@'); at >= 0 {
		local = addr[:at]
		domain = strings.ToLower(strings.TrimRight(addr[at+1:], "."))
	}
	return &model.Address{
		DisplayName: strings.TrimSpace(name),
		Address:     addr,
		LocalPart:   local,
		Domain:      domain,
		Raw:         raw,
	}
}
