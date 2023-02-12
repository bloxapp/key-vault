package launcher

import (
	"bytes"
	"context"
	"io"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/pkg/errors"
)

type execResult struct {
	stdOut   string
	stdErr   string
	exitCode int
}

func (l *Docker) inspectExecResp(ctx context.Context, containerID string, command []string) (*execResult, error) {
	execData, err := l.client.ContainerExecCreate(ctx, containerID, types.ExecConfig{
		AttachStderr: true,
		AttachStdout: true,
		Cmd:          command,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create exec command")
	}

	resp, err := l.client.ContainerExecAttach(ctx, execData.ID, types.ExecStartCheck{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to attach exec command")
	}
	defer resp.Close()

	// read the output
	var outBuf, errBuf bytes.Buffer
	outputDone := make(chan error)
	go func() {
		// StdCopy demultiplexes the stream into two buffers
		_, err = stdcopy.StdCopy(&outBuf, &errBuf, resp.Reader)
		outputDone <- err
	}()

	select {
	case err := <-outputDone:
		if err != nil {
			return nil, err
		}
		break
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	stdout, err := io.ReadAll(&outBuf)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read stdout")
	}

	stderr, err := io.ReadAll(&errBuf)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read stderr")
	}

	res, err := l.client.ContainerExecInspect(ctx, execData.ID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to inspect exec command")
	}

	return &execResult{
		exitCode: res.ExitCode,
		stdErr:   string(stderr),
		stdOut:   string(stdout),
	}, nil
}
