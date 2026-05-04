# secscan

`secscan` is a small Go MVP for local security checks on Linux hosts, with Debian
and DirectAdmin servers as the first target.

The current version is intentionally simple:

- one binary, no daemon and no agent running in the background
- CLI commands: `audit`, `detect`, `version`
- host detection from `/etc/os-release`, `runtime.GOOS`, `runtime.GOARCH`
- running service detection through `systemctl list-units --type=service --state=running`
- modular checks through `Module` and `Check` interfaces
- first module: `sshd`
- JSON output on stdout

Not included yet:

- HTML/PDF reports
- GUI report
- SMTP delivery
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
sudo ./secscan audit
```

Run every registered module, even when a matching service was not detected:

```bash
sudo ./secscan audit --all
```

Print version:

```bash
./secscan version
```

## Current SSH checks

The `sshd` module runs only when `ssh.service` or `sshd.service` is detected as
running in systemd. It reads effective OpenSSH settings with:

```bash
sshd -T
```

Checks:

- `PermitRootLogin != yes`
- `PasswordAuthentication != yes` as `warn`
- `PermitEmptyPasswords == no`

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

## Future direction

The next natural step is to add report renderers without changing the check
modules:

- `report/json` for machine-readable output
- `report/html` for a client/admin GUI-style report
- `report/smtp` for sending the generated report to a configured email address

The intended future flow:

```bash
sudo ./secscan audit --html --smtp-to admin@example.com
```

For now, the JSON report is the stable contract that later renderers can consume.
