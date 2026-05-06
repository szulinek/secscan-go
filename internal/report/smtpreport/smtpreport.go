package smtpreport

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Host               string   `json:"host"`
	Port               int      `json:"port"`
	Username           string   `json:"username"`
	Password           string   `json:"password"`
	From               string   `json:"from"`
	FromName           string   `json:"from_name,omitempty"`
	TLS                string   `json:"tls"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify"`
	DefaultTo          []string `json:"default_to,omitempty"`
}

type Message struct {
	To             []string
	Subject        string
	Body           string
	AttachmentName string
	Attachment     []byte
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, err
	}
	if config.TLS == "" {
		config.TLS = "starttls"
	}
	return config, nil
}

func ParseRecipients(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
	})

	recipients := []string{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			recipients = append(recipients, part)
		}
	}

	return recipients
}

func Send(config Config, message Message) error {
	if err := validate(config, message); err != nil {
		return err
	}

	payload, err := buildMessage(config, message)
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	client, err := smtpClient(config, addr)
	if err != nil {
		return err
	}
	defer client.Close()

	if config.Username != "" {
		auth := smtp.PlainAuth("", config.Username, config.Password, config.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	if err := client.Mail(config.From); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	for _, recipient := range message.To {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("smtp recipient %s: %w", recipient, err)
		}
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := writer.Write(payload); err != nil {
		writer.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("smtp quit: %w", err)
	}

	return nil
}

func smtpClient(config Config, addr string) (*smtp.Client, error) {
	tlsConfig := &tls.Config{
		ServerName:         config.Host,
		InsecureSkipVerify: config.InsecureSkipVerify,
	}

	dialer := &net.Dialer{Timeout: 30 * time.Second}
	switch strings.ToLower(config.TLS) {
	case "implicit", "implicit_tls", "tls":
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("smtp tls dial: %w", err)
		}
		return smtp.NewClient(conn, config.Host)
	case "none", "plain":
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("smtp dial: %w", err)
		}
		return smtp.NewClient(conn, config.Host)
	case "starttls", "":
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("smtp dial: %w", err)
		}
		client, err := smtp.NewClient(conn, config.Host)
		if err != nil {
			conn.Close()
			return nil, err
		}
		if ok, _ := client.Extension("STARTTLS"); !ok {
			client.Close()
			return nil, fmt.Errorf("smtp server does not advertise STARTTLS")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			client.Close()
			return nil, fmt.Errorf("smtp starttls: %w", err)
		}
		return client, nil
	default:
		return nil, fmt.Errorf("unsupported smtp tls mode: %s", config.TLS)
	}
}

func validate(config Config, message Message) error {
	if config.Host == "" {
		return fmt.Errorf("smtp host is required")
	}
	if config.Port <= 0 {
		return fmt.Errorf("smtp port is required")
	}
	if config.From == "" {
		return fmt.Errorf("smtp from is required")
	}
	if _, err := mail.ParseAddress(config.From); err != nil {
		return fmt.Errorf("invalid smtp from address: %w", err)
	}
	if len(message.To) == 0 {
		return fmt.Errorf("recipient is required; pass --to or set default_to in smtp config")
	}
	for _, recipient := range message.To {
		if _, err := mail.ParseAddress(recipient); err != nil {
			return fmt.Errorf("invalid recipient address %q: %w", recipient, err)
		}
	}
	if len(message.Attachment) > 0 && message.AttachmentName == "" {
		return fmt.Errorf("attachment name is required")
	}
	return nil
}

func buildMessage(config Config, message Message) ([]byte, error) {
	boundary := "secscan-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	fromAddress := mail.Address{Name: config.FromName, Address: config.From}
	from := fromAddress.String()

	var out bytes.Buffer
	writeHeader(&out, "From", from)
	writeHeader(&out, "To", strings.Join(message.To, ", "))
	writeHeader(&out, "Subject", mime.QEncoding.Encode("utf-8", message.Subject))
	writeHeader(&out, "MIME-Version", "1.0")
	writeHeader(&out, "Content-Type", `multipart/mixed; boundary="`+boundary+`"`)
	out.WriteString("\r\n")

	out.WriteString("--" + boundary + "\r\n")
	writeHeader(&out, "Content-Type", `text/plain; charset="utf-8"`)
	writeHeader(&out, "Content-Transfer-Encoding", "8bit")
	out.WriteString("\r\n")
	out.WriteString(message.Body)
	out.WriteString("\r\n\r\n")

	if len(message.Attachment) > 0 {
		out.WriteString("--" + boundary + "\r\n")
		writeHeader(&out, "Content-Type", `application/pdf; name="`+escapeFilename(message.AttachmentName)+`"`)
		writeHeader(&out, "Content-Disposition", `attachment; filename="`+escapeFilename(message.AttachmentName)+`"`)
		writeHeader(&out, "Content-Transfer-Encoding", "base64")
		out.WriteString("\r\n")
		writeBase64Lines(&out, message.Attachment)
	}
	out.WriteString("\r\n--" + boundary + "--\r\n")

	return out.Bytes(), nil
}

func writeHeader(out *bytes.Buffer, key, value string) {
	out.WriteString(key)
	out.WriteString(": ")
	out.WriteString(value)
	out.WriteString("\r\n")
}

func writeBase64Lines(out *bytes.Buffer, data []byte) {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(encoded, data)
	for len(encoded) > 76 {
		out.Write(encoded[:76])
		out.WriteString("\r\n")
		encoded = encoded[76:]
	}
	out.Write(encoded)
	out.WriteString("\r\n")
}

func escapeFilename(name string) string {
	name = strings.ReplaceAll(name, `"`, "")
	name = strings.ReplaceAll(name, "\r", "")
	name = strings.ReplaceAll(name, "\n", "")
	return name
}
