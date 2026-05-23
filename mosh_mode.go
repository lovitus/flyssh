package main

import (
	"context"
	"fmt"
	"time"

	"github.com/flyssh/flyssh/pkg/cli"
	"github.com/flyssh/flyssh/pkg/moshsession"
	"golang.org/x/crypto/ssh"
)

func runMosh(opts *cli.Options) (int, error) {
	reconnectDelay := time.Duration(opts.ReconnectDelay) * time.Second
	if reconnectDelay <= 0 {
		reconnectDelay = 3 * time.Second
	}
	connector := func() (*ssh.Client, func(), error) {
		sshConfig, clients, finalClient, err := connectChain(opts)
		if err != nil {
			return nil, nil, err
		}
		stopKeepalive := make(chan struct{})
		if sshConfig.ServerAliveInterval > 0 {
			interval := time.Duration(sshConfig.ServerAliveInterval) * time.Second
			for _, c := range clients {
				go keepAliveUntil(c, interval, sshConfig.ServerAliveCountMax, stopKeepalive)
			}
		}
		cleanup := func() {
			close(stopKeepalive)
			closeClients(clients)
		}
		return finalClient, cleanup, nil
	}
	err := moshsession.Run(context.Background(), connector, moshsession.Options{
		SessionName:    opts.MoshSession,
		ReconnectDelay: reconnectDelay,
		Verbose:        opts.Verbose,
	})
	if err != nil {
		return 255, fmt.Errorf("mosh: %w", err)
	}
	return 0, nil
}
