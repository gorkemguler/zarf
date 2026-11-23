package model

import "time"

const Version = "0.1.0"

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

type Verdict string

const (
	VerdictClean    Verdict = "CLEAN"
	VerdictLow      Verdict = "LOW"
	VerdictMedium   Verdict = "MEDIUM"
	VerdictHigh     Verdict = "HIGH"
	VerdictCritical Verdict = "CRITICAL"
)

// Report is the complete offline forensic autopsy of an .eml file.
type Report struct {
	ToolVersion   string            `json:"tool_version"`
	AnalyzedAt    time.Time         `json:"analyzed_at"`
	OfflineMode   bool              `json:"offline_mode"`
	Evidence      EvidenceManifest  `json:"evidence"`
	Score         RiskScore         `json:"score"`
	Headers       HeaderSummary     `json:"headers"`
	Identity      IdentityAnalysis  `json:"identity"`
	Hops          HopChain          `json:"hops"`
	Auth          AuthAnalysis      `json:"auth"`
	Body          BodyAnalysis      `json:"body"`
	URLs          []URLFinding      `json:"urls"`
	Attachments   []AttachmentInfo  `json:"attachments"`
	Findings      []Finding         `json:"findings"`
	IOCs          IOCSummary        `json:"iocs"`
	NestedReports []*Report         `json:"nested_reports,omitempty"`
	Recommendations []string        `json:"recommendations"`
}

// EvidenceManifest records cryptographic proof of the examined raw .eml artifact.
type EvidenceManifest struct {
	Filename   string `json:"filename"`
	SizeBytes  int64  `json:"size_bytes"`
	SHA256     string `json:"sha256"`
	SHA1       string `json:"sha1"`
	MD5        string `json:"md5"`
	LineCount  int    `json:"line_count"`
	HeaderSize int    `json:"header_size"`
	BodySize   int    `json:"body_size"`
}

// RiskScore gives an explainable 0-100 risk score broken down by forensic category.
type RiskScore struct {
	Total      int            `json:"total"`
	MaxScore   int            `json:"max_score"`
	Verdict    Verdict        `json:"verdict"`
	Categories map[string]int `json:"categories"`
	Summary    string         `json:"summary"`
}

type Address struct {
	DisplayName string `json:"display_name"`
	Address     string `json:"address"`
	LocalPart   string `json:"local_part"`
	Domain      string `json:"domain"`
	Raw         string `json:"raw"`
}

type HeaderKV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HeaderSummary struct {
	Subject       string     `json:"subject"`
	Date          string     `json:"date"`
	ParsedDate    *time.Time `json:"parsed_date,omitempty"`
	MessageID     string     `json:"message_id"`
	MessageDomain string     `json:"message_domain"`
	From          *Address   `json:"from,omitempty"`
	Sender        *Address   `json:"sender,omitempty"`
	ReplyTo       []Address  `json:"reply_to,omitempty"`
	ReturnPath    *Address   `json:"return_path,omitempty"`
	To            []Address  `json:"to,omitempty"`
	CC            []Address  `json:"cc,omitempty"`
	XMailer       string     `json:"x_mailer,omitempty"`
	UserAgent     string     `json:"user_agent,omitempty"`
	XOriginatingIP string    `json:"x_originating_ip,omitempty"`
	ContentType   string     `json:"content_type"`
	AllHeaders    []HeaderKV `json:"all_headers"`
}

type IdentityAnalysis struct {
	FromDomain                 string   `json:"from_domain"`
	ReturnPathDomain           string   `json:"return_path_domain"`
	ReplyToDomains             []string `json:"reply_to_domains,omitempty"`
	DKIMDomains                []string `json:"dkim_domains,omitempty"`
	ReturnPathMismatch         bool     `json:"return_path_mismatch"`
	ReplyToMismatch            bool     `json:"reply_to_mismatch"`
	ReplyToFreemail            bool     `json:"reply_to_freemail"`
	DisplayNameSpoof           bool     `json:"display_name_spoof"`
	DisplayNameEmbeddedEmail   string   `json:"display_name_embedded_email,omitempty"`
	DisplayNameBrandImpersonat string   `json:"display_name_brand_impersonated,omitempty"`
	MessageIDDomainMismatch    bool     `json:"message_id_domain_mismatch"`
	FromHomoglyph              bool     `json:"from_homoglyph"`
	FromPunycodeDecoded        string   `json:"from_punycode_decoded,omitempty"`
	Anomalies                  []string `json:"anomalies,omitempty"`
}

type Hop struct {
	Index         int        `json:"index"` // 1 = earliest (origin), N = final delivery
	Raw           string     `json:"raw"`
	FromHost      string     `json:"from_host"`
	FromIP        string     `json:"from_ip"`
	IPScope       string     `json:"ip_scope"` // public, private, loopback, unknown
	ByHost        string     `json:"by_host"`
	ByIP          string     `json:"by_ip"`
	Protocol      string     `json:"protocol"`
	TLS           bool       `json:"tls"`
	Cipher        string     `json:"cipher,omitempty"`
	TimestampRaw  string     `json:"timestamp_raw"`
	Timestamp     *time.Time `json:"timestamp,omitempty"`
	DelaySeconds  *float64   `json:"delay_seconds,omitempty"`
	ClockSkew     bool       `json:"clock_skew"`
	DelayAnomaly  bool       `json:"delay_anomaly"`
	Notes         []string   `json:"notes,omitempty"`
}

type HopChain struct {
	Hops              []Hop    `json:"hops"`
	OriginIP          string   `json:"origin_ip,omitempty"`
	OriginHost        string   `json:"origin_host,omitempty"`
	FinalHost         string   `json:"final_host,omitempty"`
	TotalTransitSec   *float64 `json:"total_transit_seconds,omitempty"`
	HasClockSkew      bool     `json:"has_clock_skew"`
	HasUnencryptedHop bool     `json:"has_unencrypted_hop"`
	PublicIPs         []string `json:"public_ips,omitempty"`
}

type AuthResult struct {
	Mechanism string `json:"mechanism"` // spf, dkim, dmarc, arc
	Status    string `json:"status"`    // pass, fail, softfail, neutral, none, temperror, permerror, bestguesspass
	Domain    string `json:"domain,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Source    string `json:"source,omitempty"` // Authentication-Results, Received-SPF, ARC-Authentication-Results
}

type DKIMCheck struct {
	Index            int      `json:"index"`
	Domain           string   `json:"domain"`
	Selector         string   `json:"selector"`
	Algorithm        string   `json:"algorithm"`
	Canonicalization string   `json:"canonicalization"`
	SignedHeaders    []string `json:"signed_headers"`
	DeclaredBodyHash string   `json:"declared_body_hash"`
	ComputedBodyHash string   `json:"computed_body_hash"`
	BodyHashMatch    bool     `json:"body_hash_match"`
	BodyLengthLimit  int      `json:"body_length_limit,omitempty"`
	CoversFrom       bool     `json:"covers_from"`
	CoversSubject    bool     `json:"covers_subject"`
	AlignedWithFrom  bool     `json:"aligned_with_from"`
	WeakAlgorithm    bool     `json:"weak_algorithm"`
	Note             string   `json:"note"`
}

type AuthAnalysis struct {
	SPF               *AuthResult  `json:"spf,omitempty"`
	DKIM              []AuthResult `json:"dkim,omitempty"`
	DMARC             *AuthResult  `json:"dmarc,omitempty"`
	ARC               []AuthResult `json:"arc,omitempty"`
	DKIMSignatures    []DKIMCheck  `json:"dkim_signatures,omitempty"`
	AuthHeaderPresent bool         `json:"auth_header_present"`
	CompAuth          string       `json:"comp_auth,omitempty"`
	Summary           string       `json:"summary"`
}

type SmugglingIndicator struct {
	Type     string   `json:"type"`
	Severity Severity `json:"severity"`
	Evidence string   `json:"evidence"`
	Detail   string   `json:"detail"`
}

type EmbeddedPayload struct {
	MIMEType      string   `json:"mime_type"`
	Encoding      string   `json:"encoding"`
	SizeBytes     int      `json:"size_bytes"`
	SHA256        string   `json:"sha256"`
	DetectedMagic string   `json:"detected_magic"`
	Snippet       string   `json:"snippet,omitempty"`
	Suspicious    bool     `json:"suspicious"`
	Reasons       []string `json:"reasons,omitempty"`
}

type BodyAnalysis struct {
	HasPlainText       bool                 `json:"has_plain_text"`
	HasHTML            bool                 `json:"has_html"`
	PlainText          string               `json:"plain_text"`
	RawHTML            string               `json:"raw_html"`
	SanitizedHTML      string               `json:"sanitized_html"`
	BlockedRemoteCount int                  `json:"blocked_remote_count"`
	BlockedRemoteHosts []string             `json:"blocked_remote_hosts,omitempty"`
	Smuggling          []SmugglingIndicator `json:"smuggling,omitempty"`
	EmbeddedPayloads   []EmbeddedPayload    `json:"embedded_payloads,omitempty"`
	HiddenTextSnippets []string             `json:"hidden_text_snippets,omitempty"`
	ZeroWidthCount     int                  `json:"zero_width_count"`
	BiDiOverrideCount  int                  `json:"bidi_override_count"`
	FormActions        []string             `json:"form_actions,omitempty"`
	PasswordInputCount int                  `json:"password_input_count"`
	UrgencySignals     []string             `json:"urgency_signals,omitempty"`
	MIMEPieces         int                  `json:"mime_pieces"`
}

type URLFinding struct {
	Raw               string   `json:"raw"`
	Defanged          string   `json:"defanged"`
	Scheme            string   `json:"scheme"`
	Host              string   `json:"host"`
	DecodedHost       string   `json:"decoded_host,omitempty"`
	Path              string   `json:"path"`
	Source            string   `json:"source"` // html-href, html-form, html-src, plain-text, pdf-uri, data-uri, attachment
	AnchorText        string   `json:"anchor_text,omitempty"`
	AnchorMismatch    bool     `json:"anchor_mismatch"`
	IsPunycode        bool     `json:"is_punycode"`
	IsHomoglyph       bool     `json:"is_homoglyph"`
	HomoglyphDetail   string   `json:"homoglyph_detail,omitempty"`
	ImpersonatedBrand string   `json:"impersonated_brand,omitempty"`
	IsIPAddress       bool     `json:"is_ip_address"`
	HasUserInfoAt     bool     `json:"has_userinfo_at"`
	IsShortener       bool     `json:"is_shortener"`
	SuspiciousTLD     bool     `json:"suspicious_tld"`
	RedirectTarget    string   `json:"redirect_target,omitempty"`
	RiskScore         int      `json:"risk_score"`
	Severity          Severity `json:"severity"`
	Reasons           []string `json:"reasons,omitempty"`
}

type ArchiveMember struct {
	Name             string `json:"name"`
	UncompressedSize uint64 `json:"uncompressed_size"`
	CompressedSize   uint64 `json:"compressed_size"`
	Encrypted        bool   `json:"encrypted"`
	Dangerous        bool   `json:"dangerous"`
	Note             string `json:"note,omitempty"`
}

type AttachmentInfo struct {
	Index                int                  `json:"index"`
	Filename             string               `json:"filename"`
	ContentType          string               `json:"content_type"`
	ContentDisposition   string               `json:"content_disposition"`
	ContentID            string               `json:"content_id,omitempty"`
	IsInline             bool                 `json:"is_inline"`
	SizeBytes            int                  `json:"size_bytes"`
	SHA256               string               `json:"sha256"`
	SHA1                 string               `json:"sha1"`
	MD5                  string               `json:"md5"`
	Entropy              float64              `json:"entropy"`
	Extension            string               `json:"extension"`
	DetectedMagic        string               `json:"detected_magic"`
	DetectedCategory     string               `json:"detected_category"`
	MagicMismatch        bool                 `json:"magic_mismatch"`
	DoubleExtension      bool                 `json:"double_extension"`
	HasRLOFilename       bool                 `json:"has_rlo_filename"`
	HasMacros            bool                 `json:"has_macros"`
	HasExternalTemplate  bool                 `json:"has_external_template"`
	HasEncryptedArchive  bool                 `json:"has_encrypted_archive"`
	ArchiveMembers       []ArchiveMember      `json:"archive_members,omitempty"`
	PDFIndicators        []string             `json:"pdf_indicators,omitempty"`
	ScriptIndicators     []string             `json:"script_indicators,omitempty"`
	HTMLSmuggling        []SmugglingIndicator `json:"html_smuggling,omitempty"`
	ExtractedURLs        []string             `json:"extracted_urls,omitempty"`
	RiskScore            int                  `json:"risk_score"`
	Severity             Severity             `json:"severity"`
	Reasons              []string             `json:"reasons,omitempty"`
}

type Finding struct {
	RuleID      string   `json:"rule_id"`
	Category    string   `json:"category"` // headers, auth, hops, body, urls, attachments
	Severity    Severity `json:"severity"`
	Points      int      `json:"points"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence,omitempty"`
}

type IOCSummary struct {
	IPs              []string `json:"ips"`
	DefangedIPs      []string `json:"defanged_ips"`
	Domains          []string `json:"domains"`
	DefangedDomains  []string `json:"defanged_domains"`
	URLs             []string `json:"urls"`
	DefangedURLs     []string `json:"defanged_urls"`
	Emails           []string `json:"emails"`
	FileHashesSHA256 []string `json:"file_hashes_sha256"`
}

// BatchSummary represents a compact triage entry when scanning a directory of .eml files.
type BatchSummary struct {
	ScannedAt time.Time        `json:"scanned_at"`
	Directory string           `json:"directory"`
	Total     int              `json:"total"`
	Critical  int              `json:"critical"`
	High      int              `json:"high"`
	Medium    int              `json:"medium"`
	Low       int              `json:"low"`
	Clean     int              `json:"clean"`
	Items     []BatchEntry     `json:"items"`
}

type BatchEntry struct {
	Filename    string  `json:"filename"`
	SHA256      string  `json:"sha256"`
	From        string  `json:"from"`
	Subject     string  `json:"subject"`
	Score       int     `json:"score"`
	Verdict     Verdict `json:"verdict"`
	TopFindings []string `json:"top_findings"`
	Error       string  `json:"error,omitempty"`
}
