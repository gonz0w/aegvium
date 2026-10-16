// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

type labShutdownServer interface {
	Shutdown(context.Context) error
	Close() error
}

var errLabServerJoin = errors.New("lab server did not join")

func closeLabResources(receiver io.Closer, routes *labRouteOwner, servers []labShutdownServer, results []chan error) error {
	var failures []error
	failures = append(failures, receiver.Close())
	routes.stopReloads()
	drained, joined := true, len(servers) == len(results)
	if !joined {
		failures = append(failures, errLabServerJoin)
	}
	for _, server := range servers {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := server.Shutdown(ctx)
		cancel()
		if err != nil {
			drained = false
			failures = append(failures, err, server.Close())
		}
	}
	for _, done := range results {
		select {
		case err, received := <-done:
			if !received {
				joined = false
				failures = append(failures, errLabServerJoin)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				failures = append(failures, err)
			}
		case <-time.After(time.Second):
			joined = false
			failures = append(failures, errLabServerJoin)
		}
	}
	// Serve can fail after its handlers drained. Its error must remain fatal,
	// but need not prevent retirement of resources that are no longer in use.
	if drained && joined {
		failures = append(failures, routes.close())
	}
	return errors.Join(failures...)
}
