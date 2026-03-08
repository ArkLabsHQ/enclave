package introspector_enclave

import (
	"context"
	"fmt"
	"os"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// runContainer runs a command inside a Docker container, equivalent to:
//
//	docker run --rm -v hostDir:containerDir -w containerDir -e KEY=VAL image sh -c command
//
// Stdout and stderr are streamed to os.Stdout and os.Stderr.
func runContainer(ctx context.Context, image, command, hostDir, containerDir string, env []string) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("connect to Docker: %w", err)
	}
	defer cli.Close()

	resp, err := cli.ContainerCreate(ctx,
		&container.Config{
			Image:      image,
			Cmd:        []string{"sh", "-c", command},
			WorkingDir: containerDir,
			Env:        env,
		},
		&container.HostConfig{
			Binds: []string{hostDir + ":" + containerDir},
		},
		nil, nil, "",
	)
	if err != nil {
		return fmt.Errorf("create container: %w", err)
	}
	containerID := resp.ID

	// Ensure cleanup.
	defer cli.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true})

	// Set up wait channel before starting to avoid race.
	waitCh, errCh := cli.ContainerWait(ctx, containerID, container.WaitConditionNotRunning)

	if err := cli.ContainerStart(ctx, containerID, container.StartOptions{}); err != nil {
		return fmt.Errorf("start container: %w", err)
	}

	// Stream logs to stdout/stderr.
	logReader, err := cli.ContainerLogs(ctx, containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
	})
	if err != nil {
		return fmt.Errorf("attach to container logs: %w", err)
	}
	defer logReader.Close()

	stdcopy.StdCopy(os.Stdout, os.Stderr, logReader)

	// Wait for exit.
	select {
	case result := <-waitCh:
		if result.StatusCode != 0 {
			return fmt.Errorf("container exited with code %d", result.StatusCode)
		}
		return nil
	case err := <-errCh:
		return fmt.Errorf("waiting for container: %w", err)
	}
}
