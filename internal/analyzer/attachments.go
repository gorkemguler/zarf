package analyzer

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/gorkemguler/zarf/internal/model"
	"github.com/gorkemguler/zarf/internal/parser"
)

var dangerousExtensions = map[string]bool{
	".exe": true, ".dll": true, ".scr": true, ".com": true, ".pif": true, ".cpl": true,
	".msi": true, ".msp": true, ".bat": true, ".cmd": true, ".ps1": true, ".vbs": true,
	".vbe": true, ".js": true, ".jse": true, ".wsf": true, ".wsh": true, ".hta": true,
	".lnk": true, ".iso": true, ".img": true, ".vhd": true, ".vhdx": true, ".cab": true,
	".jar": true, ".docm": true, ".xlsm": true, ".pptm": true, ".dotm": true, ".one": true,
	".chm": true, ".reg": true, ".html": true, ".htm": true, ".shtml": true, ".svg": true,
}

var decoyFirstExtensions = map[string]bool{
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".ppt": true, ".pptx": true, ".txt": true, ".jpg": true, ".jpeg": true, ".png": true,
}

var (
	rxPDFURI       = regexp.MustCompile(`/URI\s*\(([^)]+)\)`)
	rxExternalRels = regexp.MustCompile(`(?i)TargetMode\s*=\s*["']External["'][^>]*Target\s*=\s*["']([^"']+)["']|Target\s*=\s*["']([^"']+)["'][^>]*TargetMode\s*=\s*["']External["']`)
	rxScriptLOLBin = regexp.MustCompile(`(?i)\b(?:powershell(?:\.exe)?|pwsh|cmd\.exe|mshta(?:\.exe)?|rundll32|regsvr32|certutil|bitsadmin|wscript\.shell|activexobject|frombase64string|invoke-expression|\biex\b|downloadstring|urldownloadtofile|-enc(?:odedcommand)?|createobject)\b`)
)

// AnalyzeAttachments performs deep, 100% static offline inspection of every attachment
// and returns attachment metadata, extracted URLs (e.g. from PDF/HTML/LNK), and findings.
func AnalyzeAttachments(pe *parser.ParsedEmail) ([]model.AttachmentInfo, []string, []model.Finding) {
	var attachments []model.AttachmentInfo
	var extractedURLs []string
	var findings []model.Finding

	idx := 0
	for _, part := range pe.Parts {
		if !part.IsAttachment {
			continue
		}
		idx++
		info, urls := inspectAttachment(idx, part)
		attachments = append(attachments, info)
		extractedURLs = append(extractedURLs, urls...)

		// Emit top-level scored findings for each high-signal attachment risk
		if info.HasRLOFilename {
			findings = append(findings, model.Finding{
				RuleID:      "ATT-001",
				Category:    "attachments",
				Severity:    model.SeverityCritical,
				Points:      30,
				Title:       fmt.Sprintf("Attachment filename uses RLO Unicode spoofing (%s)", info.Filename),
				Description: "The attachment name embeds a Right-to-Left Override character (U+202E) to visually disguise an executable extension as a benign document.",
				Evidence:    fmt.Sprintf("filename=%q sha256=%s", info.Filename, info.SHA256[:16]),
			})
		}
		if info.MagicMismatch {
			findings = append(findings, model.Finding{
				RuleID:      "ATT-002",
				Category:    "attachments",
				Severity:    model.SeverityCritical,
				Points:      28,
				Title:       fmt.Sprintf("Attachment magic-byte / extension mismatch (%s)", info.Filename),
				Description: fmt.Sprintf("File claims extension %s, but binary header identifies it as %s.", info.Extension, info.DetectedMagic),
				Evidence:    fmt.Sprintf("%s -> actual=%s (%s)", info.Filename, info.DetectedMagic, info.DetectedCategory),
			})
		}
		if info.DoubleExtension {
			findings = append(findings, model.Finding{
				RuleID:      "ATT-003",
				Category:    "attachments",
				Severity:    model.SeverityHigh,
				Points:      22,
				Title:       fmt.Sprintf("Double-extension masquerading attachment (%s)", info.Filename),
				Description: "Filename pairs a decoy document extension with an executable, script, or HTML extension.",
				Evidence:    info.Filename,
			})
		}
		if info.HasMacros {
			findings = append(findings, model.Finding{
				RuleID:      "ATT-004",
				Category:    "attachments",
				Severity:    model.SeverityCritical,
				Points:      28,
				Title:       fmt.Sprintf("Office macros detected inside attachment (%s)", info.Filename),
				Description: "Static inspection detected embedded VBA macro structures (vbaProject.bin or OLE VBA streams).",
				Evidence:    strings.Join(info.Reasons, "; "),
			})
		}
		if info.HasExternalTemplate {
			findings = append(findings, model.Finding{
				RuleID:      "ATT-005",
				Category:    "attachments",
				Severity:    model.SeverityCritical,
				Points:      30,
				Title:       fmt.Sprintf("OOXML remote template / external relationship injection (%s)", info.Filename),
				Description: "An Office XML .rels file contains TargetMode=\"External\", a technique used to fetch remote malicious templates or leak NTLM hashes.",
				Evidence:    strings.Join(info.ExtractedURLs, ", "),
			})
		}
		if len(info.HTMLSmuggling) > 0 {
			findings = append(findings, model.Finding{
				RuleID:      "ATT-006",
				Category:    "attachments",
				Severity:    model.SeverityCritical,
				Points:      30,
				Title:       fmt.Sprintf("HTML/SVG smuggling attachment (%s)", info.Filename),
				Description: "An attached HTML or SVG file contains active JavaScript/Blob smuggling or payload drop logic.",
				Evidence:    fmt.Sprintf("%s (%d smuggling indicators)", info.Filename, len(info.HTMLSmuggling)),
			})
		}
		if len(info.PDFIndicators) > 0 {
			sev := model.SeverityMedium
			pts := 12
			for _, pi := range info.PDFIndicators {
				if strings.Contains(pi, "/JavaScript") || strings.Contains(pi, "/JS") || strings.Contains(pi, "/Launch") || strings.Contains(pi, "/OpenAction") {
					sev = model.SeverityHigh
					pts = 20
					break
				}
			}
			findings = append(findings, model.Finding{
				RuleID:      "ATT-007",
				Category:    "attachments",
				Severity:    sev,
				Points:      pts,
				Title:       fmt.Sprintf("Active/risky PDF constructs in %s", info.Filename),
				Description: "Static PDF analysis found active scripting, auto-action, embedded file, or launch tags.",
				Evidence:    strings.Join(info.PDFIndicators, ", "),
			})
		}
		if info.HasEncryptedArchive {
			findings = append(findings, model.Finding{
				RuleID:      "ATT-008",
				Category:    "attachments",
				Severity:    model.SeverityHigh,
				Points:      18,
				Title:       fmt.Sprintf("Password-protected archive attachment (%s)", info.Filename),
				Description: "Encrypted archives are routinely used in phishing campaigns to evade email gateway antivirus inspection.",
				Evidence:    info.Filename,
			})
		}
		if len(info.ScriptIndicators) > 0 {
			findings = append(findings, model.Finding{
				RuleID:      "ATT-009",
				Category:    "attachments",
				Severity:    model.SeverityCritical,
				Points:      28,
				Title:       fmt.Sprintf("Suspicious execution / LOLBin strings in %s", info.Filename),
				Description: "Static string inspection detected script execution or living-off-the-land binary invocation markers.",
				Evidence:    strings.Join(info.ScriptIndicators, ", "),
			})
		}
		if info.DetectedCategory == "executable" || info.DetectedCategory == "shortcut" || info.DetectedCategory == "disk-image" {
			findings = append(findings, model.Finding{
				RuleID:      "ATT-010",
				Category:    "attachments",
				Severity:    model.SeverityCritical,
				Points:      30,
				Title:       fmt.Sprintf("High-risk binary payload attached (%s — %s)", info.Filename, info.DetectedMagic),
				Description: "Email carries an executable binary, Windows LNK shortcut, or ISO disk image.",
				Evidence:    fmt.Sprintf("magic=%s size=%d entropy=%.2f", info.DetectedMagic, info.SizeBytes, info.Entropy),
			})
		}
	}

	return attachments, uniqueStrings(extractedURLs), findings
}

func inspectAttachment(idx int, part parser.ParsedPart) (model.AttachmentInfo, []string) {
	data := part.Body
	h256 := sha256.Sum256(data)
	h1 := sha1.Sum(data)
	hm := md5.Sum(data)

	fname := part.Filename
	if fname == "" {
		fname = fmt.Sprintf("unnamed_part_%d", idx)
	}

	ext := strings.ToLower(filepath.Ext(fname))
	magicName, magicCat := IdentifyMagic(data, ext)
	ent := shannonEntropy(data)

	info := model.AttachmentInfo{
		Index:              idx,
		Filename:           fname,
		ContentType:        part.MediaType,
		ContentDisposition: part.ContentDisposition,
		ContentID:          part.ContentID,
		IsInline:           part.IsInline,
		SizeBytes:          len(data),
		SHA256:             hex.EncodeToString(h256[:]),
		SHA1:               hex.EncodeToString(h1[:]),
		MD5:                hex.EncodeToString(hm[:]),
		Entropy:            math.Round(ent*100) / 100,
		Extension:          ext,
		DetectedMagic:      magicName,
		DetectedCategory:   magicCat,
	}

	score := 0
	var urls []string
	addReason := func(pts int, reason string) {
		score += pts
		info.Reasons = append(info.Reasons, reason)
	}

	// 1. Filename RLO spoofing
	for _, r := range fname {
		if r == 0x202E || r == 0x202D || r == 0x2066 || r == 0x2067 {
			info.HasRLOFilename = true
			addReason(50, "Filename embeds Unicode BiDi/RLO control character to mask true extension")
			break
		}
	}

	// 2. Double extension check (e.g. invoice.pdf.exe, report.docx.html)
	baseNoExt := strings.TrimSuffix(strings.ToLower(fname), ext)
	secondExt := strings.ToLower(filepath.Ext(baseNoExt))
	if secondExt != "" && decoyFirstExtensions[secondExt] && dangerousExtensions[ext] {
		info.DoubleExtension = true
		addReason(40, fmt.Sprintf("Double extension masquerading (%s%s)", secondExt, ext))
	}

	// 3. Dangerous extension check
	if dangerousExtensions[ext] {
		addReason(22, fmt.Sprintf("High-risk file extension (%s)", ext))
	}

	// 4. Magic-byte vs extension mismatch
	if isMagicMismatch(ext, magicCat) {
		info.MagicMismatch = true
		addReason(45, fmt.Sprintf("Extension %s contradicts detected magic %s (%s)", ext, magicName, magicCat))
	}

	// 5. High entropy warning (packed/encrypted payload, excluding naturally compressed images/zips/pdfs)
	if len(data) > 1024 && ent > 7.65 && magicCat != "image" && magicCat != "archive" && magicCat != "ooxml" && magicCat != "pdf" {
		addReason(15, fmt.Sprintf("Very high Shannon entropy (%.2f/8.00) suggests encryption or packing", ent))
	}

	// 6. Format-specific deep static inspection
	switch magicCat {
	case "archive", "ooxml":
		inspectZipOrOOXML(data, &info, &urls, addReason)
	case "ole2":
		inspectOLE2(data, &info, addReason)
	case "pdf":
		inspectPDF(data, &info, &urls, addReason)
	case "shortcut":
		inspectLNK(data, &info, &urls, addReason)
	case "html", "svg":
		inspectHTMLAttachment(data, &info, &urls, addReason)
	case "script":
		inspectScriptAttachment(data, &info, &urls, addReason)
	case "executable", "disk-image":
		addReason(55, fmt.Sprintf("Dangerous binary/container format (%s)", magicName))
	}

	// Also run script/HTML scan if extension is HTML/SVG/script even if magic detected generic text
	if (ext == ".html" || ext == ".htm" || ext == ".shtml" || ext == ".svg") && magicCat != "html" && magicCat != "svg" {
		inspectHTMLAttachment(data, &info, &urls, addReason)
	}
	if (ext == ".ps1" || ext == ".vbs" || ext == ".js" || ext == ".hta" || ext == ".bat" || ext == ".cmd") && magicCat != "script" {
		inspectScriptAttachment(data, &info, &urls, addReason)
	}

	info.ExtractedURLs = uniqueStrings(urls)
	if score > 100 {
		score = 100
	}
	info.RiskScore = score
	info.Severity = scoreToSeverity(score)
	return info, info.ExtractedURLs
}

func inspectZipOrOOXML(data []byte, info *model.AttachmentInfo, urls *[]string, addReason func(int, string)) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return
	}
	isOOXML := false
	dangerousNested := 0

	for _, f := range zr.File {
		lowName := strings.ToLower(f.Name)
		encrypted := (f.Flags & 0x1) != 0
		if encrypted {
			info.HasEncryptedArchive = true
		}

		member := model.ArchiveMember{
			Name:             f.Name,
			UncompressedSize: f.UncompressedSize64,
			CompressedSize:   f.CompressedSize64,
			Encrypted:        encrypted,
		}

		if lowName == "[content_types].xml" || strings.HasPrefix(lowName, "word/") || strings.HasPrefix(lowName, "xl/") || strings.HasPrefix(lowName, "ppt/") {
			isOOXML = true
		}

		// Macro project inside OOXML
		if strings.HasSuffix(lowName, "vbaproject.bin") || strings.Contains(lowName, "vbadata.xml") {
			info.HasMacros = true
			member.Dangerous = true
			member.Note = "Embedded VBA macro binary"
			addReason(45, fmt.Sprintf("Contains VBA macro stream (%s)", f.Name))
		}

		// Check dangerous nested archive members
		mExt := strings.ToLower(filepath.Ext(lowName))
		if dangerousExtensions[mExt] && !strings.HasPrefix(lowName, "word/") && !strings.HasPrefix(lowName, "xl/") && !strings.HasPrefix(lowName, "ppt/") {
			member.Dangerous = true
			member.Note = fmt.Sprintf("Dangerous nested file (%s)", mExt)
			dangerousNested++
		}

		// Zip bomb compression ratio check
		if f.CompressedSize64 > 0 && f.UncompressedSize64 > 10*1024*1024 && (f.UncompressedSize64/f.CompressedSize64) > 100 {
			member.Dangerous = true
			member.Note = "Extreme compression ratio (potential zip bomb)"
			addReason(25, fmt.Sprintf("Extreme compression ratio in member %s", f.Name))
		}

		// Inspect OOXML .rels files for TargetMode="External" (remote template / NTLM leak)
		if strings.HasSuffix(lowName, ".rels") && !encrypted && f.UncompressedSize64 < 512*1024 {
			if rc, err := f.Open(); err == nil {
				content, _ := io.ReadAll(io.LimitReader(rc, 512*1024))
				_ = rc.Close()
				for _, m := range rxExternalRels.FindAllStringSubmatch(string(content), -1) {
					target := firstNonEmpty(m[1], m[2])
					if target == "" {
						continue
					}
					// Hyperlink relationships are normal; attachedTemplate / oleObject / frame external refs are dangerous!
					lowRel := strings.ToLower(string(content))
					if strings.Contains(lowRel, "attachedtemplate") || strings.Contains(lowRel, "oleobject") || strings.Contains(lowRel, "frame") || strings.HasPrefix(strings.ToLower(target), "file:") || strings.HasPrefix(target, "\\\\") {
						info.HasExternalTemplate = true
						member.Dangerous = true
						member.Note = "External template / remote object relationship"
						addReason(50, fmt.Sprintf("External OOXML template/object reference -> %s", target))
					}
					if strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
						*urls = append(*urls, target)
					}
				}
			}
		}

		if len(info.ArchiveMembers) < 40 {
			info.ArchiveMembers = append(info.ArchiveMembers, member)
		}
	}

	if isOOXML {
		info.DetectedCategory = "ooxml"
		info.DetectedMagic = "Office Open XML (OOXML/ZIP)"
	}
	if info.HasEncryptedArchive {
		addReason(30, "Archive contains password-protected/encrypted entries")
	}
	if dangerousNested > 0 {
		addReason(38, fmt.Sprintf("Archive contains %d dangerous nested executable/script/HTML file(s)", dangerousNested))
	}
}

func inspectOLE2(data []byte, info *model.AttachmentInfo, addReason func(int, string)) {
	low := bytes.ToLower(data)
	macroMarkers := [][]byte{
		[]byte("_vba_project"), []byte("vba_project"), []byte("macros"),
		[]byte("autoopen"), []byte("autoexec"), []byte("document_open"), []byte("workbook_open"),
	}
	foundMacros := []string{}
	for _, mk := range macroMarkers {
		if bytes.Contains(low, mk) {
			foundMacros = append(foundMacros, string(mk))
		}
	}
	if len(foundMacros) > 0 {
		info.HasMacros = true
		addReason(45, fmt.Sprintf("OLE2 VBA macro markers: %s", strings.Join(foundMacros, ", ")))
	}
	if m := rxScriptLOLBin.FindAllString(string(data), 6); len(m) > 0 {
		info.ScriptIndicators = uniqueStrings(m)
		addReason(30, fmt.Sprintf("OLE2 embedded execution strings: %s", strings.Join(info.ScriptIndicators, ", ")))
	}
}

func inspectPDF(data []byte, info *model.AttachmentInfo, urls *[]string, addReason func(int, string)) {
	markers := []struct {
		Token string
		Pts   int
	}{
		{"/JavaScript", 30},
		{"/JS", 25},
		{"/Launch", 35},
		{"/OpenAction", 22},
		{"/AA", 15},
		{"/EmbeddedFile", 20},
		{"/RichMedia", 18},
		{"/XFA", 15},
		{"/SubmitForm", 20},
		{"/GoToR", 15},
	}
	for _, mk := range markers {
		if bytes.Contains(data, []byte(mk.Token)) {
			info.PDFIndicators = append(info.PDFIndicators, mk.Token)
			addReason(mk.Pts, fmt.Sprintf("PDF contains %s tag", mk.Token))
		}
	}
	for _, m := range rxPDFURI.FindAllSubmatch(data, 20) {
		if len(m) >= 2 {
			u := strings.TrimSpace(string(m[1]))
			if strings.HasPrefix(strings.ToLower(u), "http://") || strings.HasPrefix(strings.ToLower(u), "https://") {
				*urls = append(*urls, u)
			}
		}
	}
	if len(*urls) > 0 && len(info.PDFIndicators) == 0 {
		info.PDFIndicators = append(info.PDFIndicators, fmt.Sprintf("/URI (%d link(s))", len(*urls)))
	}
}

func inspectLNK(data []byte, info *model.AttachmentInfo, urls *[]string, addReason func(int, string)) {
	addReason(45, "Windows Shell Link (.lnk) attachment — frequently abused for initial access")
	// Extract printable ASCII and UTF-16LE strings from the binary LNK
	combined := extractASCIIAndUTF16Strings(data)
	if matches := rxScriptLOLBin.FindAllString(combined, 10); len(matches) > 0 {
		info.ScriptIndicators = uniqueStrings(matches)
		addReason(40, fmt.Sprintf("LNK invokes suspicious binary/flags: %s", strings.Join(info.ScriptIndicators, ", ")))
	}
	for _, u := range rxPlainURL.FindAllString(combined, 10) {
		*urls = append(*urls, cleanTrailingPunct(u))
	}
}

func inspectHTMLAttachment(data []byte, info *model.AttachmentInfo, urls *[]string, addReason func(int, string)) {
	s := string(data)
	smug, payloads := ScanHTMLSmuggling(s)
	if rxScriptTag.MatchString(s) {
		smug = appendUniqueSmuggling(smug, model.SmugglingIndicator{
			Type:     "inline-script-tag",
			Severity: model.SeverityHigh,
			Evidence: truncateStr(rxScriptTag.FindString(s), 120),
			Detail:   "HTML/SVG attachment contains executable <script> block.",
		})
	}
	if rxPasswordInp.MatchString(s) {
		smug = appendUniqueSmuggling(smug, model.SmugglingIndicator{
			Type:     "credential-form",
			Severity: model.SeverityCritical,
			Evidence: "<input type=password>",
			Detail:   "HTML attachment renders a local credential-harvesting login page.",
		})
	}
	info.HTMLSmuggling = smug
	if len(smug) > 0 {
		addReason(45, fmt.Sprintf("HTML/SVG smuggling & active script indicators (%d)", len(smug)))
	}
	for _, p := range payloads {
		if p.Suspicious {
			addReason(35, fmt.Sprintf("Embedded data: URI payload (%s, %s)", p.MIMEType, p.DetectedMagic))
		}
	}
	for _, u := range rxPlainURL.FindAllString(s, 20) {
		*urls = append(*urls, cleanTrailingPunct(u))
	}
}

func inspectScriptAttachment(data []byte, info *model.AttachmentInfo, urls *[]string, addReason func(int, string)) {
	s := string(data)
	if matches := rxScriptLOLBin.FindAllString(s, 10); len(matches) > 0 {
		info.ScriptIndicators = uniqueStrings(matches)
		addReason(45, fmt.Sprintf("Script invokes suspicious commands: %s", strings.Join(info.ScriptIndicators, ", ")))
	}
	for _, u := range rxPlainURL.FindAllString(s, 15) {
		*urls = append(*urls, cleanTrailingPunct(u))
	}
}

// IdentifyMagic classifies binary headers completely offline without external libraries.
func IdentifyMagic(data []byte, ext string) (name string, category string) {
	if len(data) == 0 {
		return "Empty file", "empty"
	}
	hasPrefix := func(sig ...byte) bool {
		return bytes.HasPrefix(data, sig)
	}
	switch {
	case hasPrefix(0x4D, 0x5A):
		return "Windows PE Executable (MZ)", "executable"
	case hasPrefix(0x7F, 0x45, 0x4C, 0x46):
		return "ELF Executable", "executable"
	case hasPrefix(0xCF, 0xFA, 0xED, 0xFE) || hasPrefix(0xFE, 0xED, 0xFA, 0xCF) || hasPrefix(0xCA, 0xFE, 0xBA, 0xBE):
		return "Mach-O Executable", "executable"
	case hasPrefix(0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00):
		return "Windows Shell Link (LNK)", "shortcut"
	case hasPrefix(0x25, 0x50, 0x44, 0x46, 0x2D):
		return "PDF Document", "pdf"
	case hasPrefix(0x50, 0x4B, 0x03, 0x04) || hasPrefix(0x50, 0x4B, 0x05, 0x06):
		return "ZIP Archive / OOXML", "archive"
	case hasPrefix(0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1):
		return "OLE2 Compound Document (DOC/XLS/MSG)", "ole2"
	case hasPrefix(0x7B, 0x5C, 0x72, 0x74, 0x66):
		return "Rich Text Format (RTF)", "rtf"
	case hasPrefix(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07):
		return "RAR Archive", "archive"
	case hasPrefix(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C):
		return "7-Zip Archive", "archive"
	case hasPrefix(0x1F, 0x8B):
		return "GZIP Compressed", "archive"
	case hasPrefix(0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D):
		return "Microsoft OneNote (.one)", "onenote"
	case hasPrefix(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A):
		return "PNG Image", "image"
	case hasPrefix(0xFF, 0xD8, 0xFF):
		return "JPEG Image", "image"
	case hasPrefix(0x47, 0x49, 0x46, 0x38):
		return "GIF Image", "image"
	case len(data) >= 12 && bytes.Equal(data[0:4], []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP")):
		return "WebP Image", "image"
	case len(data) > 0x8006 && bytes.Equal(data[0x8001:0x8006], []byte("CD001")):
		return "ISO 9660 Disk Image", "disk-image"
	}

	// Text-based sniffing (HTML, SVG, XML, scripts)
	head := strings.ToLower(strings.TrimSpace(string(data[:minInt(len(data), 1024)])))
	switch {
	case strings.HasPrefix(head, "<!doctype html") || strings.Contains(head, "<html") || strings.Contains(head, "<script"):
		return "HTML Document", "html"
	case strings.Contains(head, "<svg"):
		return "SVG Vector Graphic", "svg"
	case strings.HasPrefix(head, "#!/") || ext == ".ps1" || ext == ".vbs" || ext == ".js" || ext == ".bat" || ext == ".cmd" || ext == ".hta":
		return "Script / Text", "script"
	case isMostlyText(data[:minInt(len(data), 512)]):
		return "Plain Text", "text"
	default:
		return "Unknown Binary", "binary"
	}
}

func isMagicMismatch(ext, magicCat string) bool {
	if ext == "" || magicCat == "empty" || magicCat == "binary" {
		return false
	}
	expected := map[string][]string{
		".pdf":  {"pdf"},
		".docx": {"archive", "ooxml"}, ".xlsx": {"archive", "ooxml"}, ".pptx": {"archive", "ooxml"},
		".docm": {"archive", "ooxml"}, ".xlsm": {"archive", "ooxml"}, ".zip": {"archive", "ooxml"},
		".doc":  {"ole2", "rtf", "archive", "ooxml"}, ".xls": {"ole2", "archive", "ooxml"},
		".png":  {"image"}, ".jpg": {"image"}, ".jpeg": {"image"}, ".gif": {"image"}, ".webp": {"image"},
		".txt":  {"text", "script"}, ".csv": {"text"},
		".html": {"html", "text"}, ".htm": {"html", "text"}, ".svg": {"svg", "text", "html"},
	}
	allowed, ok := expected[ext]
	if !ok {
		return false
	}
	for _, c := range allowed {
		if c == magicCat {
			return false
		}
	}
	return true
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	total := float64(len(data))
	ent := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		ent -= p * math.Log2(p)
	}
	return ent
}

func extractASCIIAndUTF16Strings(data []byte) string {
	var sb strings.Builder
	// ASCII runs >= 4
	var run []byte
	for _, b := range data {
		if b >= 32 && b <= 126 {
			run = append(run, b)
		} else {
			if len(run) >= 4 {
				sb.Write(run)
				sb.WriteByte(' ')
			}
			run = run[:0]
		}
	}
	if len(run) >= 4 {
		sb.Write(run)
		sb.WriteByte(' ')
	}
	// UTF-16LE runs >= 4
	var u16 []uint16
	for i := 0; i+1 < len(data); i += 2 {
		v := binary.LittleEndian.Uint16(data[i : i+2])
		if v >= 32 && v <= 126 {
			u16 = append(u16, v)
		} else {
			if len(u16) >= 4 {
				sb.WriteString(string(utf16.Decode(u16)))
				sb.WriteByte(' ')
			}
			u16 = u16[:0]
		}
	}
	if len(u16) >= 4 {
		sb.WriteString(string(utf16.Decode(u16)))
	}
	return sb.String()
}

func isMostlyText(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	printable := 0
	for _, c := range b {
		if (c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t' || c >= 0xC0 {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) > 0.85
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
