package process

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"sync"

	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("Honeytrap")

// CriticalLevel defines a int type which is used to signal the critical nature of a
// command/script to be executed.
type CriticalLevel int

// Contains possible critical level values for commands execution
const (
	Normal CriticalLevel = iota + 1
	Warning
	RedAlert
)

const (
	shellMessage = `
	Shell: %q
	Status: %t (%q)
	Reason: \n%+q
	Script: %+q
`
	commandMessage = `
	Command: %q
	Arguments: %+q
	Status: %t (%q)
	Reason: \n%+q
`
)

// Command defines the command to be executed and it's arguments
type Command struct {
	Name  string        `json:"name" toml:"name"`
	Level CriticalLevel `json:"level" toml:"level"`
	Args  []string      `json:"args" toml:"args"`
}

// Run executes the giving command and returns the bytes.Buffer for both
// the Stdout and Stderr.
func (c Command) Run(ctx context.Context, out, werr io.Writer) error {
	proc := exec.Command(c.Name, c.Args...)
	proc.Stdout = out
	proc.Stderr = werr

	log.Infof("Process : Command : Begin Execution : %q : %+q", c.Name, c.Args)

	if err := proc.Start(); err != nil {
		log.Errorf("Process : Error : Command : Begin Execution : %q : %q", c.Name, c.Args)

		if c.Level > Normal {
			log.Debugf("Process : Debug : Command : %s : %+q", c.Name, fmt.Sprintf(commandMessage, c.Name, c.Args, false, "Failed", err.Error()))
		}

		return err
	}

	go func() {
		<-ctx.Done()
		if proc.Process != nil {
			proc.Process.Kill()
		}
	}()

	if err := proc.Wait(); err != nil {
		log.Errorf("Process : Error : Command : Begin Execution : %q : %q", c.Name, c.Args)

		if c.Level > Normal {
			log.Debugf("Process : Debug : Command : %s : %+q", c.Name, fmt.Sprintf(commandMessage, c.Name, c.Args, false, "Failed", err.Error()))
		}

		if c.Level > Warning {
			return err
		}

		return nil
	}

	if c.Level > Normal {
		log.Debugf("Process : Debug : Command : %s : %+q", c.Name, fmt.Sprintf(commandMessage, c.Name, c.Args, proc.ProcessState.Success(), proc.ProcessState.String()))
	}

	return nil
}

//============================================================================================

// SyncProcess defines a struct which is used to execute a giving set of
// script values.
type SyncProcess struct {
	Commands []Command `json:"commands"`
}

// SyncExec executes the giving series of commands attached to the
// process.
func (p SyncProcess) SyncExec(ctx context.Context, pipeOut, pipeErr io.Writer) error {
	for _, command := range p.Commands {
		if err := command.Run(ctx, pipeOut, pipeErr); err != nil {
			return err
		}
	}

	return nil
}

//============================================================================================

// AsyncProcess defines a struct which is used to execute a giving set of
// script values.
type AsyncProcess struct {
	Commands []Command `json:"commands"`
}

// AsyncExec executes the giving series of commands attached to the
// process.
func (p AsyncProcess) AsyncExec(ctx context.Context, pipeOut, pipeErr io.Writer) error {
	var waiter sync.WaitGroup

	for _, command := range p.Commands {
		go func(cmd Command) {
			waiter.Add(1)
			defer waiter.Done()

			cmd.Run(ctx, pipeOut, pipeErr)
		}(command)
	}

	waiter.Wait()
	return nil
}

//============================================================================================

// SyncScripts defines a struct which is used to execute a giving set of
// shell script.
type SyncScripts struct {
	Scripts []ScriptProcess `json:"commands"`
}

// SyncExec executes the giving series of commands attached to the
// process.
func (p SyncScripts) SyncExec(ctx context.Context, pipeOut, pipeErr io.Writer) error {
	for _, command := range p.Scripts {
		if err := command.Exec(ctx, pipeOut, pipeErr); err != nil {
			return err
		}
	}

	return nil
}

//============================================================================================

// ScriptProcess defines a shell script execution structure which attempts to copy
// given script into a local file path and attempts to execute content.
// Shell states the shell to be used for execution: /bin/sh, /bin/bash
type ScriptProcess struct {
	Shell  string        `json:"shell" toml:"shell"`
	Source string        `json:"source" toml:"source"`
	Level  CriticalLevel `json:"level" toml:"level"`
}

// Exec executes a copy of the giving script source in a temporary file which it then executes
// the contents.
func (c ScriptProcess) Exec(ctx context.Context, pipeOut, pipeErr io.Writer) error {
	log.Infof("Process : Shell Script : Begin Execution : %q : %q", c.Shell, c.Source)

	tmpFile, err := ioutil.TempFile("/tmp", "proc-shell")
	if err != nil {
		log.Errorf("Process : Error : Command : Begin Execution : %q : %+q", c.Shell, err)
		return err
	}

	if _, err := tmpFile.Write([]byte(c.Source)); err != nil {
		log.Errorf("Process : Error : Command : Begin Execution : %q : %+q", c.Shell, err)
		tmpFile.Close()
		return err
	}

	if err := tmpFile.Sync(); err != nil {
		log.Errorf("Process : Error : Command : Begin Execution : %q : %+q", c.Shell, err)
		tmpFile.Close()
		return err
	}

	tmpFile.Close()

	defer os.Remove(tmpFile.Name())

	proc := exec.Command(c.Shell, tmpFile.Name())
	proc.Stdout = pipeOut
	proc.Stderr = pipeErr

	if err := proc.Start(); err != nil {
		log.Errorf("Process : Error : Command : Begin Execution : %q : %+q", c.Shell, err)
		return err
	}

	go func() {
		<-ctx.Done()
		if proc.Process != nil {
			proc.Process.Kill()
		}
	}()

	if err := proc.Wait(); err != nil {
		log.Errorf("Process : Error : Command : Begin Execution : %q : %q", c.Shell, c.Source)

		if c.Level > Normal {
			log.Debugf("Process : Debug : Command : %+q", fmt.Sprintf(shellMessage, c.Shell, false, "Failed", err.Error(), c.Source))
		}

		if c.Level > Warning {
			return err
		}

		return nil
	}

	if c.Level > Normal {
		log.Debugf("Process : Debug : Command :  %+q", fmt.Sprintf(shellMessage, c.Shell, proc.ProcessState.Success(), proc.ProcessState.String(), err.Error(), c.Source))
	}

	return nil
}
