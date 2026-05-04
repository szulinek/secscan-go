package execx

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type LocalRunner struct{}

func (LocalRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, CommandError{
			Command: strings.TrimSpace(name + " " + strings.Join(args, " ")),
			Output:  strings.TrimSpace(string(output)),
			Err:     err,
		}
	}

	return output, nil
}

type CommandError struct {
	Command string
	Output  string
	Err     error
}

func (e CommandError) Error() string {
	if e.Output == "" {
		return fmt.Sprintf("%s: %v", e.Command, e.Err)
	}

	return fmt.Sprintf("%s: %v: %s", e.Command, e.Err, e.Output)
}

func (e CommandError) Unwrap() error {
	return e.Err
}
