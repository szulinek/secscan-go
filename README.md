# secscan

`secscan` is a small Go MVP for local security checks on Linux hosts, with Debian
and DirectAdmin servers as the first target.

The current version is intentionally simple:

- one binary, no daemon and no agent running in the background
- CLI commands: `audit`, `detect`, `report`, `version`
- host detection from `/etc/os-release`, `runtime.GOOS`, `runtime.GOARCH`
- hostname and non-loopback IP address inventory
- running service detection through `systemctl list-units --type=service --state=running`
- modular checks through `Module` and `Check` interfaces
- first deep-check module: `sshd`
- Linux and Nginx baseline checks
- detection-only modules for common DirectAdmin/Linux services
- JSON output on stdout
- HTML and PDF reports for client/admin views
- SMTP delivery for client PDF reports

Not included yet:

- central panel
- uploads
- automatic fixes

## Build

```bash
go build -o secscan ./cmd/secscan
```

For a Debian x86_64 target:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o secscan-linux-amd64 ./cmd/secscan
```

## Run

Detect host and running services:

```bash
./secscan detect
```

Run the audit and print JSON:

```bash
sudo ./secscan audit --format json
```

Run every registered module, even when a matching service was not detected:

```bash
sudo ./secscan audit --all --format json
```

Save an audit and render HTML reports:

```bash
sudo ./secscan audit --all --format json > audit.json
./secscan report --input audit.json --format html --type client > client-report.html
./secscan report --input audit.json --format html --type admin > admin-report.html
```

Render a PDF report:

```bash
sudo apt-get update
sudo apt-get install -y wkhtmltopdf

./secscan report --input audit.json --format pdf --type client > client-report.pdf
./secscan report --input audit.json --format pdf --type admin > admin-report.pdf
```

If `wkhtmltopdf` is not in `PATH`, pass it explicitly:

```bash
./secscan report --input audit.json --format pdf --type client \
  --wkhtmltopdf /usr/bin/wkhtmltopdf > client-report.pdf
```

## SMTP delivery

Create your local SMTP config from the template:

```bash
cp config/smtp.example.json config/smtp.json
nano config/smtp.json
```

The real config file is ignored by git. Fill in:

```json
{
  "host": "smtp.example.com",
  "port": 587,
  "username": "audit@example.com",
  "password": "CHANGE_ME",
  "from": "audit@example.com",
  "from_name": "LH.pl Security Audit",
  "tls": "starttls",
  "insecure_skip_verify": false,
  "default_to": []
}
```

Send a client PDF report to a specific address:

```bash
./secscan send-report \
  --input audit.json \
  --type client \
  --smtp-config config/smtp.json \
  --to klient@example.com
```

You can also put a default recipient into `default_to` and omit `--to`.

Print version:

```bash
./secscan version
```

## Current modules

The `sshd` module runs only when `ssh.service` or `sshd.service` is detected as
running in systemd. It reads effective OpenSSH settings with:

```bash
sshd -T
```

SSH checks:

- `PermitRootLogin != yes`
- `PasswordAuthentication != yes` as `warn`
- `PermitEmptyPasswords == no`

Linux checks:

- unattended-upgrades installed/enabled
- host firewall detected through CSF/LFD, nftables, iptables, or UFW signals

Nginx checks:

- `server_tokens off` checked through `nginx -T`

Detection-only modules currently emit one INFO check named `Service detected`.
They are intentionally shallow so deeper security checks can be added module by
module later:

- `php_fpm`
- `directadmin`
- `mysql_mariadb`
- `exim`
- `dovecot`
- `redis`
- `named_bind`
- `pure_ftpd`
- `firewall_csf_lfd`

## Ansible

`secscan` is designed to work well with Ansible: copy the binary to many hosts,
run the audit with privilege escalation, and collect JSON reports on the
controller.

Build the Linux binary first:

```bash
mkdir -p dist
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dist/secscan-linux-amd64 ./cmd/secscan
```

Copy the example inventory and adjust hosts:

```bash
cp deploy/ansible/inventory.example.ini deploy/ansible/inventory.ini
```

Run the audit across all hosts:

```bash
ansible-playbook -i deploy/ansible/inventory.ini deploy/ansible/secscan-audit.yml \
  -e secscan_binary="$(pwd)/dist/secscan-linux-amd64" \
  -e secscan_all_modules=true
```

Reports are saved locally on the Ansible controller:

```text
deploy/ansible/reports/<inventory_hostname>.json
```

Render one of the collected reports:

```bash
./secscan report --input deploy/ansible/reports/server1.json --format html --type client > client-report.html
./secscan report --input deploy/ansible/reports/server1.json --format html --type admin > admin-report.html
```

Render and send a client PDF:

```bash
./secscan send-report \
  --input deploy/ansible/reports/server1.json \
  --type client \
  --smtp-config config/smtp.json \
  --to klient@example.com
```

## Future direction

The JSON report is the stable data contract. HTML/PDF rendering and SMTP
delivery are implemented on top of that contract.

The intended future flow:

```bash
sudo ./secscan audit --all --format json > audit.json
./secscan send-report --input audit.json --type client --smtp-config config/smtp.json --to admin@example.com
```
