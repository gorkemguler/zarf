package analyzer

import (
	"fmt"
	"strings"
	"unicode"
)

// Common multi-part public suffixes so org-domain comparison handles e.g. .com.tr, .gov.tr, .co.uk.
var multiPartPublicSuffixes = map[string]bool{
	"com.tr": true, "org.tr": true, "net.tr": true, "gov.tr": true, "edu.tr": true, "bel.tr": true,
	"pol.tr": true, "mil.tr": true, "k12.tr": true, "av.tr": true, "dr.tr": true, "gen.tr": true,
	"co.uk": true, "org.uk": true, "gov.uk": true, "ac.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "gov.au": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "go.jp": true,
	"com.br": true, "org.br": true, "gov.br": true,
	"co.in": true, "gov.in": true, "com.mx": true, "com.cn": true,
	"com.sg": true, "com.hk": true, "co.za": true, "co.nz": true,
	"com.ua": true, "com.pl": true, "co.il": true, "com.sa": true,
}

// OrgDomain returns the organizational domain (eTLD+1) for alignment checks.
func OrgDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(strings.TrimRight(host, ".")))
	if host == "" {
		return ""
	}
	if idx := strings.LastIndexByte(host, ':'); idx > 0 && !strings.Contains(host, "]") {
		host = host[:idx]
	}
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	lastTwo := parts[len(parts)-2] + "." + parts[len(parts)-1]
	if multiPartPublicSuffixes[lastTwo] && len(parts) >= 3 {
		return parts[len(parts)-3] + "." + lastTwo
	}
	return lastTwo
}

// DecodePunycodeDomain decodes any xn-- labels in a domain according to RFC 3492.
func DecodePunycodeDomain(domain string) (decoded string, hasPunycode bool) {
	labels := strings.Split(strings.ToLower(strings.TrimSpace(domain)), ".")
	out := make([]string, len(labels))
	for i, lbl := range labels {
		if strings.HasPrefix(lbl, "xn--") {
			if dec, err := decodePunycodeLabel(lbl[4:]); err == nil {
				out[i] = dec
				hasPunycode = true
				continue
			}
		}
		out[i] = lbl
	}
	return strings.Join(out, "."), hasPunycode
}

// RFC 3492 Punycode decoder (pure Go stdlib).
func decodePunycodeLabel(input string) (string, error) {
	const (
		base        = 36
		tMin        = 1
		tMax        = 26
		skew        = 38
		damp        = 700
		initialBias = 72
		initialN    = 128
	)

	var output []rune
	idx := strings.LastIndexByte(input, '-')
	pos := 0
	if idx > 0 {
		for _, r := range input[:idx] {
			if r >= 0x80 {
				return "", fmt.Errorf("non-basic code point")
			}
			output = append(output, r)
		}
		pos = idx + 1
	}

	n := initialN
	i := 0
	bias := initialBias

	adapt := func(delta, numPoints int, firstTime bool) int {
		if firstTime {
			delta /= damp
		} else {
			delta /= 2
		}
		delta += delta / numPoints
		k := 0
		for delta > ((base-tMin)*tMax)/2 {
			delta /= base - tMin
			k += base
		}
		return k + (((base - tMin + 1) * delta) / (delta + skew))
	}

	decodeDigit := func(b byte) (int, bool) {
		switch {
		case b >= 'a' && b <= 'z':
			return int(b - 'a'), true
		case b >= 'A' && b <= 'Z':
			return int(b - 'A'), true
		case b >= '0' && b <= '9':
			return int(b-'0') + 26, true
		default:
			return 0, false
		}
	}

	for pos < len(input) {
		oldi := i
		w := 1
		for k := base; ; k += base {
			if pos >= len(input) {
				return "", fmt.Errorf("punycode truncated")
			}
			digit, ok := decodeDigit(input[pos])
			if !ok {
				return "", fmt.Errorf("invalid punycode digit")
			}
			pos++
			if digit > (0x7fffffff-i)/w {
				return "", fmt.Errorf("punycode overflow")
			}
			i += digit * w
			t := k - bias
			if t < tMin {
				t = tMin
			} else if t > tMax {
				t = tMax
			}
			if digit < t {
				break
			}
			if w > 0x7fffffff/(base-t) {
				return "", fmt.Errorf("punycode weight overflow")
			}
			w *= base - t
		}
		outLen := len(output) + 1
		bias = adapt(i-oldi, outLen, oldi == 0)
		if i/outLen > 0x10FFFF-n {
			return "", fmt.Errorf("punycode codepoint overflow")
		}
		n += i / outLen
		i %= outLen
		if !unicode.IsPrint(rune(n)) && n < 0x80 {
			return "", fmt.Errorf("invalid rune")
		}
		// Insert rune(n) at position i
		output = append(output, 0)
		copy(output[i+1:], output[i:])
		output[i] = rune(n)
		i++
	}
	return string(output), nil
}

// Cyrillic, Greek, and Latin-extended confusable lookalike characters mapped to ASCII skeleton.
var confusableRunes = map[rune]rune{
	// Cyrillic
	'а': 'a', 'А': 'a',
	'е': 'e', 'Е': 'e',
	'о': 'o', 'О': 'o',
	'р': 'p', 'Р': 'p',
	'с': 'c', 'С': 'c',
	'х': 'x', 'Х': 'x',
	'у': 'y', 'У': 'y',
	'і': 'i', 'І': 'i',
	'ј': 'j', 'Ј': 'j',
	'ѕ': 's', 'Ѕ': 's',
	'һ': 'h', 'Һ': 'h',
	'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
	'к': 'k', 'К': 'k',
	'м': 'm', 'М': 'm',
	'т': 't', 'Т': 't',
	'н': 'h', 'Н': 'h',
	'в': 'b', 'В': 'b',
	'п': 'n',
	// Greek
	'α': 'a', 'Α': 'a',
	'ε': 'e', 'Ε': 'e',
	'ο': 'o', 'Ο': 'o',
	'ρ': 'p', 'Ρ': 'p',
	'ν': 'v', 'ι': 'i',
	'κ': 'k', 'Κ': 'k',
	'τ': 't', 'Τ': 't',
	'χ': 'x', 'Χ': 'x',
	'υ': 'u',
	// Latin lookalikes & diacritics often used in IDN spoofing
	'ı': 'i', 'İ': 'i',
	'ğ': 'g', 'ş': 's', 'ç': 'c', 'ö': 'o', 'ü': 'u',
	'á': 'a', 'à': 'a', 'â': 'a', 'ä': 'a', 'ã': 'a', 'å': 'a', 'ā': 'a',
	'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e', 'ē': 'e',
	'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i', 'ī': 'i',
	'ó': 'o', 'ò': 'o', 'ô': 'o', 'õ': 'o', 'ø': 'o', 'ō': 'o',
	'ú': 'u', 'ù': 'u', 'û': 'u', 'ū': 'u',
	'ñ': 'n', 'ý': 'y', 'ÿ': 'y', 'ß': 's',
	'ℓ': 'l', 'ⅰ': 'i', 'ⅼ': 'l',
}

// DetectHomoglyph inspects a decoded domain for non-ASCII confusable scripts,
// mixed scripts (e.g. Cyrillic + Latin), or visual ASCII spoofs (rn->m, 0->o, 1->l).
func DetectHomoglyph(domain string) (isHomoglyph bool, skeleton string, detail string) {
	decoded, hasPuny := DecodePunycodeDomain(domain)
	var hasLatin, hasCyrillic, hasGreek, hasNonASCII bool
	var confusables []string
	var skel strings.Builder

	for _, r := range decoded {
		if r == '.' || r == '-' {
			skel.WriteRune(r)
			continue
		}
		if r > 127 {
			hasNonASCII = true
			if unicode.In(r, unicode.Cyrillic) {
				hasCyrillic = true
			} else if unicode.In(r, unicode.Greek) {
				hasGreek = true
			}
		} else if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLatin = true
		}

		if mapped, ok := confusableRunes[r]; ok {
			skel.WriteRune(mapped)
			if r > 127 && (unicode.In(r, unicode.Cyrillic) || unicode.In(r, unicode.Greek)) {
				confusables = append(confusables, fmt.Sprintf("%q (U+%04X -> %q)", r, r, mapped))
			}
		} else {
			skel.WriteRune(unicode.ToLower(r))
		}
	}

	rawSkel := skel.String()
	// Normalize common ASCII visual confusables for brand similarity comparison
	normSkel := strings.NewReplacer("rn", "m", "vv", "w", "0", "o", "1", "l").Replace(rawSkel)

	if hasLatin && (hasCyrillic || hasGreek) {
		return true, normSkel, fmt.Sprintf("Mixed-script IDN homoglyph (%s): %s", decoded, strings.Join(confusables, ", "))
	}
	if len(confusables) > 0 {
		return true, normSkel, fmt.Sprintf("Confusable non-Latin characters in %s: %s", decoded, strings.Join(confusables, ", "))
	}
	if hasPuny && hasNonASCII {
		return true, normSkel, fmt.Sprintf("Punycode IDN domain decodes to %q (skeleton: %s)", decoded, rawSkel)
	}
	return false, normSkel, ""
}

// High-value global + Turkish brands frequently targeted in phishing & BEC campaigns.
type brandTarget struct {
	Name             string
	Keywords         []string
	LegitimateDomains []string
}

var trackedBrands = []brandTarget{
	{Name: "Microsoft", Keywords: []string{"microsoft", "office365", "microsoft365", "outlook", "onedrive", "sharepoint", "teams"}, LegitimateDomains: []string{"microsoft.com", "office.com", "office365.com", "live.com", "outlook.com", "microsoftonline.com", "sharepoint.com"}},
	{Name: "Google", Keywords: []string{"google", "gmail", "google workspace", "google drive"}, LegitimateDomains: []string{"google.com", "gmail.com", "accounts.google.com", "googleapis.com"}},
	{Name: "Apple", Keywords: []string{"apple", "icloud", "apple id"}, LegitimateDomains: []string{"apple.com", "icloud.com"}},
	{Name: "PayPal", Keywords: []string{"paypal"}, LegitimateDomains: []string{"paypal.com"}},
	{Name: "DocuSign", Keywords: []string{"docusign"}, LegitimateDomains: []string{"docusign.com", "docusign.net"}},
	{Name: "Amazon", Keywords: []string{"amazon", "aws"}, LegitimateDomains: []string{"amazon.com", "amazon.com.tr", "amazonaws.com"}},
	{Name: "DHL", Keywords: []string{"dhl"}, LegitimateDomains: []string{"dhl.com", "dhl.com.tr"}},
	{Name: "GitHub", Keywords: []string{"github"}, LegitimateDomains: []string{"github.com", "githubusercontent.com"}},
	{Name: "Adobe", Keywords: []string{"adobe", "acrobat"}, LegitimateDomains: []string{"adobe.com"}},
	{Name: "Okta", Keywords: []string{"okta"}, LegitimateDomains: []string{"okta.com"}},
	{Name: "Dropbox", Keywords: []string{"dropbox"}, LegitimateDomains: []string{"dropbox.com"}},
	{Name: "e-Devlet", Keywords: []string{"e-devlet", "edevlet", "turkiye.gov"}, LegitimateDomains: []string{"turkiye.gov.tr", "gov.tr"}},
	{Name: "Garanti BBVA", Keywords: []string{"garanti", "garantibbva"}, LegitimateDomains: []string{"garantibbva.com.tr", "garanti.com.tr"}},
	{Name: "İş Bankası", Keywords: []string{"isbank", "iş bankası", "isbankasi"}, LegitimateDomains: []string{"isbank.com.tr"}},
	{Name: "Ziraat Bankası", Keywords: []string{"ziraat", "ziraatbank"}, LegitimateDomains: []string{"ziraatbank.com.tr"}},
	{Name: "Yapı Kredi", Keywords: []string{"yapikredi", "yapı kredi"}, LegitimateDomains: []string{"yapikredi.com.tr"}},
	{Name: "Akbank", Keywords: []string{"akbank"}, LegitimateDomains: []string{"akbank.com", "akbank.com.tr"}},
	{Name: "QNB Finansbank", Keywords: []string{"qnbfinansbank", "finansbank"}, LegitimateDomains: []string{"qnbfinansbank.com", "qnb.com.tr"}},
	{Name: "PTT / HGS", Keywords: []string{"ptt", "hgs"}, LegitimateDomains: []string{"ptt.gov.tr", "pttavm.com", "hgsmusteri.ptt.gov.tr"}},
	{Name: "Turkcell", Keywords: []string{"turkcell"}, LegitimateDomains: []string{"turkcell.com.tr"}},
	{Name: "Trendyol", Keywords: []string{"trendyol"}, LegitimateDomains: []string{"trendyol.com"}},
	{Name: "GİB / Vergi", Keywords: []string{"gelir idaresi", "ivd.gib", "e-tebligat"}, LegitimateDomains: []string{"gib.gov.tr"}},
}

// MatchImpersonatedBrand checks if a domain (using its homoglyph skeleton) mimics a tracked brand
// while NOT belonging to that brand's legitimate domains.
func MatchImpersonatedBrand(host string) (brand string, reason string) {
	org := OrgDomain(host)
	if org == "" {
		return "", ""
	}
	_, skel, _ := DetectHomoglyph(host)
	skelOrg := OrgDomain(skel)
	// Strip TLD from skeleton for label comparison
	skelLabel := strings.Split(skelOrg, ".")[0]
	fullLower := strings.ToLower(skel)

	for _, b := range trackedBrands {
		isLegit := false
		for _, legit := range b.LegitimateDomains {
			if org == legit || strings.HasSuffix(host, "."+legit) {
				isLegit = true
				break
			}
		}
		if isLegit {
			continue
		}
		for _, kw := range b.Keywords {
			kwClean := strings.ReplaceAll(strings.ReplaceAll(kw, " ", ""), "-", "")
			if len(kwClean) < 4 {
				continue
			}
			fullNoHyphen := strings.ReplaceAll(fullLower, "-", "")
			if strings.Contains(fullNoHyphen, kwClean) {
				return b.Name, fmt.Sprintf("Domain %q contains brand token %q outside legitimate %s domains", host, kw, b.Name)
			}
			// Check Levenshtein typosquat distance <= 1 for labels of length >= 5
			if len(kwClean) >= 5 && len(skelLabel) >= 5 {
				if dist := levenshtein(skelLabel, kwClean); dist > 0 && dist <= 1 {
					return b.Name, fmt.Sprintf("Domain label %q is a 1-edit typosquat/homoglyph of %s (%q)", skelLabel, b.Name, kwClean)
				}
			}
		}
	}
	return "", ""
}

// MatchDisplayNameBrand checks if an email Display Name claims to be a tracked brand
// while the sender domain is unrelated.
func MatchDisplayNameBrand(displayName, senderDomain string) string {
	dn := strings.ToLower(strings.TrimSpace(displayName))
	if dn == "" || senderDomain == "" {
		return ""
	}
	org := OrgDomain(senderDomain)
	for _, b := range trackedBrands {
		matched := false
		for _, kw := range b.Keywords {
			if len(kw) >= 4 && strings.Contains(dn, kw) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		isLegit := false
		for _, legit := range b.LegitimateDomains {
			if org == legit || strings.HasSuffix(senderDomain, "."+legit) {
				isLegit = true
				break
			}
		}
		if !isLegit {
			return b.Name
		}
	}
	return ""
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			curr[j] = m
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

// Defang converts URLs, domains, and IPs into analyst-safe defanged IOCs.
func DefangURL(raw string) string {
	s := raw
	if strings.HasPrefix(strings.ToLower(s), "https://") {
		s = "hxxps://" + s[8:]
	} else if strings.HasPrefix(strings.ToLower(s), "http://") {
		s = "hxxp://" + s[7:]
	}
	// Defang dots only in authority/host portion
	schemeIdx := strings.Index(s, "://")
	if schemeIdx >= 0 {
		rest := s[schemeIdx+3:]
		slashIdx := strings.IndexAny(rest, "/?#")
		if slashIdx >= 0 {
			host := strings.ReplaceAll(rest[:slashIdx], ".", "[.]")
			return s[:schemeIdx+3] + host + rest[slashIdx:]
		}
		return s[:schemeIdx+3] + strings.ReplaceAll(rest, ".", "[.]")
	}
	return strings.ReplaceAll(s, ".", "[.]")
}

func DefangHost(h string) string {
	return strings.ReplaceAll(h, ".", "[.]")
}
