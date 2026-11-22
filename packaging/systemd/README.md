# systemd unit examples

Examples only: the `.deb` and `.rpm` ship them under
`/usr/share/doc/setura/examples/systemd/` and never enable or start anything.

- `system/setura-gateway.service` is a hardened system service. Put a snapshot
  at `/etc/setura/gateway.json`, then
  `sudo cp setura-gateway.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now setura-gateway`.
  It binds loopback only; change `--bind` and the ports deliberately.
- `user/*.service` are the `systemd --user` units that `scripts/deploy-remote.sh`
  generates for the demo stack (gateway plus two identity backends), with the
  script's default ports. They expect the layout `~/zyvor-setura-gateway/{bin,config}`.
  Copy them to `~/.config/systemd/user/`, run `systemctl --user daemon-reload`,
  and `loginctl enable-linger $USER` so they survive logout.
