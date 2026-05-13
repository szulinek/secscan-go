package phpfpm

import (
	"strings"
	"testing"
)

func TestParseINIHandlesCommentsQuotesAndValues(t *testing.T) {
	config := ParseINI(strings.Join([]string{
		"; expose_php = On",
		`expose_php = "Off" ; trailing comment`,
		`error_log = "/var/log/php#error.log"`,
		`disable_functions = exec,passthru # inline comment`,
	}, "\n"))

	if config.Values["expose_php"] != "Off" {
		t.Fatalf("unexpected expose_php: %#v", config.Values)
	}
	if config.Values["error_log"] != "/var/log/php#error.log" {
		t.Fatalf("quoted hash should be preserved, got %q", config.Values["error_log"])
	}
	if config.Values["disable_functions"] != "exec,passthru" {
		t.Fatalf("unexpected disable_functions: %q", config.Values["disable_functions"])
	}
}

func TestParsePoolConfigSectionsAndPHPValues(t *testing.T) {
	pools := ParsePoolConfig("8.3", sourceDirectAdmin, "/tmp/domusspolka.conf", strings.Join([]string{
		"[domusspolka]",
		"user = $pool",
		"group = $pool",
		"listen = /usr/local/php83/sockets/$pool.sock",
		"pm.max_children = 40",
		"php_admin_value[mail.log] = /home/user/.php/php-mail.log",
		"php_value[open_basedir] = /home/user:/tmp",
		"security.limit_extensions = .php",
		"session.save_path = /home/user/.php/session",
		"",
		"[global]",
		"error_log = /dev/null",
		"",
		"[main]",
		"listen = /tmp/main.sock",
	}, "\n"))

	if len(pools) != 3 {
		t.Fatalf("expected 3 sections, got %d", len(pools))
	}
	app := pools[0]
	if app.Pool != "domusspolka" || app.Values["user"] != "$pool" || app.Values["group"] != "$pool" {
		t.Fatalf("unexpected app pool: %#v", app)
	}
	if app.PHPAdminValues["mail.log"] != "/home/user/.php/php-mail.log" {
		t.Fatalf("mail.log was not parsed: %#v", app.PHPAdminValues)
	}
	if app.PHPValues["open_basedir"] != "/home/user:/tmp" {
		t.Fatalf("open_basedir override was not parsed: %#v", app.PHPValues)
	}
	if app.Values["security.limit_extensions"] != ".php" || app.Values["session.save_path"] != "/home/user/.php/session" {
		t.Fatalf("expected pool keys to be preserved: %#v", app.Values)
	}
	if pools[1].Pool != "global" || pools[1].Values["error_log"] != "/dev/null" {
		t.Fatalf("global section not parsed: %#v", pools[1])
	}
	if pools[2].Pool != "main" || pools[2].Values["listen"] != "/tmp/main.sock" {
		t.Fatalf("main section not parsed: %#v", pools[2])
	}
}
