package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/gorkemguler/zarf/internal/analyzer"
	"github.com/gorkemguler/zarf/internal/export"
	"github.com/gorkemguler/zarf/internal/model"
	"github.com/gorkemguler/zarf/internal/samples"
	"github.com/gorkemguler/zarf/internal/web"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "inspect":
		os.Exit(cmdInspect(os.Args[2:]))
	case "batch":
		os.Exit(cmdBatch(os.Args[2:]))
	case "serve":
		os.Exit(cmdServe(os.Args[2:], false))
	case "app":
		os.Exit(cmdServe(os.Args[2:], true))
	case "demo":
		os.Exit(cmdDemo(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Printf("zarf v%s (%s/%s · pure Go · 100%% offline · 0 network calls)\n", model.Version, runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		printUsage()
	default:
		// Convenience: allow `zarf path/to/file.eml` directly
		if _, err := os.Stat(os.Args[1]); err == nil {
			os.Exit(cmdInspect(os.Args[1:]))
		}
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`zarf v%s — Offline .eml phishing autopsy & email forensics in one Go binary.
Zero external dependencies · Zero network calls · CLI + Embedded Web UI.

Usage:
  zarf inspect [flags] <file.eml | ->   Dissect a single .eml file (or stdin via '-')
  zarf batch   [flags] <directory>      Triage all .eml files in a directory
  zarf serve   [flags] [file.eml]       Launch the embedded localhost Web UI workbench
  zarf app     [flags] [file.eml]       Desktop app mode: launch Web UI & open browser automatically
  zarf demo    [flags]                  Run built-in synthetic phishing specimens (or export them)
  zarf version                          Print version info

Inspect flags:
  --format    text|json|md|stix|takedown|iocs   Output format (default: text)
  --lang      en|tr                             Language for takedown draft (default: en)
  --out       <path>                            Write output to a file instead of stdout
  --no-color                                    Disable ANSI terminal colors
  --fail-above <0-100>                          Exit with code 2 if score >= threshold (SOAR/CI)

Serve / App flags:
  --addr          <host:port>                   Listen address (default: 127.0.0.1:8088)
  --open                                        Automatically open default browser (default true for 'app')
  --allow-ui-stop                               Show a 'Quit Server' button in the local Web UI

Demo flags:
  --sample     <id|all>                         Sample ID or 'all' (default: homoglyph-cred-phish)
  --format     text|json|md|stix|takedown       Output format (default: text)
  --export-dir <dir>                            Write all synthetic .eml samples to a directory
`, model.Version)
}

func cmdInspect(args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	format := fs.String("format", "text", "Output format: text|json|md|stix|takedown|iocs")
	lang := fs.String("lang", "en", "Language for takedown draft: en|tr")
	outPath := fs.String("out", "", "Write output to file")
	noColor := fs.Bool("no-color", false, "Disable ANSI colors")
	failAbove := fs.Int("fail-above", -1, "Exit with code 2 when risk score >= threshold")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "error: missing <file.eml> argument (or '-' for stdin)")
		return 1
	}

	target := fs.Arg(0)
	var rep *model.Report
	var err error

	if target == "-" {
		raw, rErr := io.ReadAll(os.Stdin)
		if rErr != nil {
			fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", rErr)
			return 1
		}
		rep, err = analyzer.AnalyzeBytes("stdin.eml", raw)
	} else {
		rep, err = analyzer.AnalyzeFile(target)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	output, err := formatReport(rep, *format, *lang, *noColor || *outPath != "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	if err := writeOutput(*outPath, output); err != nil {
		fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
		return 1
	}

	if *failAbove >= 0 && rep.Score.Total >= *failAbove {
		return 2
	}
	return 0
}

func cmdBatch(args []string) int {
	fs := flag.NewFlagSet("batch", flag.ExitOnError)
	format := fs.String("format", "text", "Output format: text|json")
	outPath := fs.String("out", "", "Write output to file")
	noColor := fs.Bool("no-color", false, "Disable ANSI colors")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "error: missing <directory> argument")
		return 1
	}

	bs, err := analyzer.AnalyzeBatch(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	var output string
	switch strings.ToLower(*format) {
	case "json":
		b, _ := json.MarshalIndent(bs, "", "  ")
		output = string(b) + "\n"
	case "text":
		output = export.RenderBatchTerminal(bs, export.ShouldUseColor(*noColor || *outPath != ""))
	default:
		fmt.Fprintf(os.Stderr, "unsupported batch format: %s\n", *format)
		return 1
	}

	if err := writeOutput(*outPath, output); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func cmdServe(args []string, desktopMode bool) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8088", "HTTP listen address (localhost recommended)")
	openBrowser := fs.Bool("open", desktopMode, "Automatically open default web browser")
	allowStop := fs.Bool("allow-ui-stop", desktopMode, "Allow stopping the server from the local Web UI")
	_ = fs.Parse(args)

	srv := web.NewServer()

	// Preload any .eml files supplied as positional arguments
	for _, f := range fs.Args() {
		if item, err := srv.PreloadFile(f); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not preload %s: %v\n", f, err)
		} else {
			fmt.Printf("  preloaded  %s  ->  score %d/100 (%s)\n", item.Filename, item.Report.Score.Total, item.Report.Score.Verdict)
		}
	}

	ln, actualAddr, err := listenWithFallback(*addr, *openBrowser)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen error: %v\n", err)
		return 1
	}

	url := "http://" + actualAddr
	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	stopCh := make(chan struct{}, 1)
	triggerStop := func() {
		select {
		case stopCh <- struct{}{}:
		default:
		}
	}
	if *allowStop {
		srv.SetShutdownFunc(triggerStop)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	fmt.Printf("\n  ZARF v%s  ·  Offline .eml Phishing Autopsy Workbench\n", model.Version)
	fmt.Printf("  Listening  %s  (100%% offline · strict CSP · 0 outbound calls)\n", url)
	fmt.Printf("  Press Ctrl+C to stop.\n\n")

	if *openBrowser {
		go func() {
			time.Sleep(250 * time.Millisecond)
			_ = launchBrowser(url)
		}()
	}

	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			return 1
		}
	case <-sigCh:
	case <-stopCh:
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	return 0
}

func listenWithFallback(addr string, allowFallback bool) (net.Listener, string, error) {
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		return ln, ln.Addr().String(), nil
	}
	if !allowFallback {
		return nil, "", err
	}
	// In desktop/app mode, try a few adjacent localhost ports before falling back to an ephemeral port.
	for port := 8089; port <= 8099; port++ {
		cand := fmt.Sprintf("127.0.0.1:%d", port)
		if ln2, err2 := net.Listen("tcp", cand); err2 == nil {
			return ln2, ln2.Addr().String(), nil
		}
	}
	ln3, err3 := net.Listen("tcp", "127.0.0.1:0")
	if err3 != nil {
		return nil, "", err
	}
	return ln3, ln3.Addr().String(), nil
}

func launchBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

func cmdDemo(args []string) int {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	sampleID := fs.String("sample", "homoglyph-cred-phish", "Sample ID or 'all'")
	format := fs.String("format", "text", "Output format: text|json|md|stix|takedown|iocs")
	lang := fs.String("lang", "en", "Language for takedown draft: en|tr")
	exportDir := fs.String("export-dir", "", "Write all synthetic .eml samples into directory")
	noColor := fs.Bool("no-color", false, "Disable ANSI colors")
	_ = fs.Parse(args)

	if *exportDir != "" {
		if err := os.MkdirAll(*exportDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "error creating dir: %v\n", err)
			return 1
		}
		for _, s := range samples.All() {
			p := filepath.Join(*exportDir, s.Filename)
			if err := os.WriteFile(p, s.Raw, 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "error writing %s: %v\n", p, err)
				return 1
			}
			fmt.Printf("wrote %s (%d bytes)\n", p, len(s.Raw))
		}
		return 0
	}

	var list []samples.Sample
	if *sampleID == "all" {
		list = samples.All()
	} else {
		s, ok := samples.ByID(*sampleID)
		if !ok {
			fmt.Fprintf(os.Stderr, "unknown sample %q. Available:\n", *sampleID)
			for _, av := range samples.All() {
				fmt.Fprintf(os.Stderr, "  - %s (%s)\n", av.ID, av.Name)
			}
			return 1
		}
		list = []samples.Sample{*s}
	}

	for i, s := range list {
		if i > 0 {
			fmt.Println(strings.Repeat("═", 84))
		}
		rep, err := analyzer.AnalyzeBytes(s.Filename, s.Raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error analyzing %s: %v\n", s.ID, err)
			return 1
		}
		out, err := formatReport(rep, *format, *lang, *noColor)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		fmt.Print(out)
	}
	return 0
}

func formatReport(rep *model.Report, format, lang string, noColor bool) (string, error) {
	switch strings.ToLower(format) {
	case "text", "cli":
		return export.RenderTerminal(rep, export.ShouldUseColor(noColor)), nil
	case "json":
		b, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	case "md", "markdown":
		return export.RenderMarkdown(rep), nil
	case "stix", "stix21":
		b, err := export.RenderSTIX21(rep)
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	case "takedown":
		return export.RenderTakedownDraft(rep, lang), nil
	case "iocs":
		var b strings.Builder
		for _, ip := range rep.IOCs.DefangedIPs {
			b.WriteString("IP\t" + ip + "\n")
		}
		for _, d := range rep.IOCs.DefangedDomains {
			b.WriteString("DOMAIN\t" + d + "\n")
		}
		for _, u := range rep.IOCs.DefangedURLs {
			b.WriteString("URL\t" + u + "\n")
		}
		for _, h := range rep.IOCs.FileHashesSHA256 {
			b.WriteString("SHA256\t" + h + "\n")
		}
		return b.String(), nil
	default:
		return "", fmt.Errorf("unsupported format %q (use text|json|md|stix|takedown|iocs)", format)
	}
}

func writeOutput(outPath, content string) error {
	if outPath == "" {
		_, err := io.WriteString(os.Stdout, content)
		return err
	}
	return os.WriteFile(outPath, []byte(content), 0o644)
}
