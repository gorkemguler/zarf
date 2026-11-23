package parser

import (
	"strings"
	"testing"
)

func TestParseEMLAndRFC2047Turkish(t *testing.T) {
	raw := []byte("From: =?UTF-8?B?R8O2cmtlbSBHw7xsZXI=?= <gorkem@example.com.tr>\r\n" +
		"Subject: =?ISO-8859-9?Q?Acil_=DEifre_G=FCncelleme?=\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=\"b1\"\r\n" +
		"\r\n" +
		"--b1\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"\r\n" +
		"Merhaba d=C3=BCnya!\r\n" +
		"--b1\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<p>Merhaba</p>\r\n" +
		"--b1--\r\n")

	pe, err := ParseEML("turkish.eml", raw)
	if err != nil {
		t.Fatalf("ParseEML failed: %v", err)
	}
	if len(pe.Evidence.SHA256) != 64 {
		t.Fatalf("expected 64-char sha256, got %q", pe.Evidence.SHA256)
	}
	from := ParseAddress(pe.HeaderMap.Get("From"))
	if from == nil || from.DisplayName != "Görkem Güler" || from.Domain != "example.com.tr" {
		t.Fatalf("unexpected parsed From: %+v", from)
	}
	subj := DecodeRFC2047(pe.HeaderMap.Get("Subject"))
	if subj != "Acil Şifre Güncelleme" {
		t.Fatalf("expected Turkish ISO-8859-9 subject 'Acil Şifre Güncelleme', got %q", subj)
	}
	if len(pe.PlainTexts) != 1 || !strings.Contains(pe.PlainTexts[0], "Merhaba dünya!") {
		t.Fatalf("expected decoded quoted-printable plain text, got %v", pe.PlainTexts)
	}
	if len(pe.HTMLBodies) != 1 || !strings.Contains(pe.HTMLBodies[0], "<p>Merhaba</p>") {
		t.Fatalf("expected html body, got %v", pe.HTMLBodies)
	}
}

func TestParseNestedRFC822(t *testing.T) {
	nested := "From: inner@evil.xyz\r\nSubject: Inner Phish\r\n\r\nInner body\r\n"
	outer := "From: reporter@corp.example\r\n" +
		"Subject: Fwd: suspicious\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"mix1\"\r\n" +
		"\r\n" +
		"--mix1\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"See attached email.\r\n" +
		"--mix1\r\n" +
		"Content-Type: message/rfc822; name=\"phish.eml\"\r\n" +
		"Content-Disposition: attachment; filename=\"phish.eml\"\r\n" +
		"\r\n" +
		nested +
		"--mix1--\r\n"

	pe, err := ParseEML("outer.eml", []byte(outer))
	if err != nil {
		t.Fatalf("ParseEML failed: %v", err)
	}
	if len(pe.NestedEMLs) != 1 {
		t.Fatalf("expected 1 nested EML, got %d", len(pe.NestedEMLs))
	}
	if !strings.Contains(string(pe.NestedEMLs[0]), "Inner Phish") {
		t.Fatalf("unexpected nested EML body: %q", string(pe.NestedEMLs[0]))
	}
}
