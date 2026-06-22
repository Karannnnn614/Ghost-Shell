# ghostshell Ansible callback plugin

Records Ansible playbook runs into the ghostshell central store.

## Install

The plugin ships at `/usr/share/ghostshell/ansible/ghostshell.py` (installed by the deb/rpm).

## Enable

**Via environment variables (per-run):**
```bash
export ANSIBLE_CALLBACK_PLUGINS=/usr/share/ghostshell/ansible
export ANSIBLE_CALLBACKS_ENABLED=ghostshell
ansible-playbook site.yml
```

**Via ansible.cfg (persistent):**
```ini
[defaults]
callback_plugins   = /usr/share/ghostshell/ansible
callbacks_enabled  = ghostshell
```

## View runs

```bash
sudo ghostshell ansible list
sudo ghostshell ansible show <runid>
```

## Requirements

- `ghostshell` binary on `PATH` on the **controller** host
- `ghostshell-daemon` daemon running (or fail-open: saves to `~/.local/share/ghostshell/ansible/`)
- Python 3.6+ (Ansible's own interpreter)

## Fail-open

If `ghostshell-daemon` is unreachable the run is saved to
`~/.local/share/ghostshell/ansible/<runid>.ajsonl` (unencrypted, owner-only `0600`).
The playbook run is never aborted due to ghostshell failures.
