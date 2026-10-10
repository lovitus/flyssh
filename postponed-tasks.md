# Deferred work

- Bound SSH route establishment through unresponsive SOCKS/SSH handshakes. The current GUI gateway liveness timeout applies after the route is established; `ssh.NewClientConn` and hop channel opens can still wait indefinitely during initial authentication/reconnection. Cover real stalled handshakes and interactive prompts before changing shared connection setup.
- Verify Xshell/Xftp and SecureCRT transfer-resume UI on a user-authorized Windows desktop. Hosted acceptance covers native Wingui transfer handlers, real rsync, pinned SSH gateway reconnection and binary channel transport; it does not certify proprietary-client rz/sz or SFTP resume behavior.
