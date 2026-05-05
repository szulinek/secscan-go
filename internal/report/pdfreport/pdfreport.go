package pdfreport

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"secscan/internal/audit"
	"secscan/internal/report/htmlreport"
)

type Options struct {
	Binary    string
	ExtraArgs []string
}

func Render(w io.Writer, report audit.Report, reportType htmlreport.Type, options Options) error {
	var html bytes.Buffer
	if err := htmlreport.Render(&html, report, reportType); err != nil {
		return err
	}

	return RenderHTML(w, html.Bytes(), options)
}

func RenderHTML(w io.Writer, html []byte, options Options) error {
	binary := options.Binary
	if binary == "" {
		binary = "wkhtmltopdf"
	}
	if _, err := exec.LookPath(binary); err != nil {
		return fmt.Errorf("%s not found in PATH; install wkhtmltopdf or pass --wkhtmltopdf /path/to/wkhtmltopdf", binary)
	}

	dir, err := os.MkdirTemp("", "secscan-pdf-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	htmlPath := filepath.Join(dir, "report.html")
	pdfPath := filepath.Join(dir, "report.pdf")
	if err := os.WriteFile(htmlPath, html, 0600); err != nil {
		return err
	}

	args := append([]string{}, options.ExtraArgs...)
	args = append(args, "--quiet", htmlPath, pdfPath)

	var stderr bytes.Buffer
	cmd := exec.Command(binary, args...)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		details := bytes.TrimSpace(stderr.Bytes())
		if len(details) > 0 {
			return fmt.Errorf("run %s: %w: %s", binary, err, string(details))
		}
		return fmt.Errorf("run %s: %w", binary, err)
	}

	pdf, err := os.ReadFile(pdfPath)
	if err != nil {
		return err
	}
	if _, err := w.Write(pdf); err != nil {
		return err
	}

	return nil
}
