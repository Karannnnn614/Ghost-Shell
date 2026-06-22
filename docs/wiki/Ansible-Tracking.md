# Ansible Tracking

ghostshell can record Ansible playbook runs on the **controller** host (the machine running `ansible-playbook`). Each run is stored encrypted in the central store alongside terminal sessions, browsable with `ghostshell ansible list` / `ghostshell ansible show`.

## How it works

```
ansible-playbook (controller)
  └─ ghostshell callback plugin (/usr/share/ghostshell/ansible/ghostshell.py)
       └─ pipes JSON-lines events to: ghostshell ansible-ingest (subprocess)
            └─ connects to ghostshell-daemon over /run/ghostshell-daemon.sock
                 └─ ghostshell-daemon encrypts + writes
                      /var/lib/ghostshell/<user>/ansible/<runid>.ajsonl
```

Events captured per run: `run` (metadata), `play`, `task` (per host: module, status, rc, stdout/stderr), `stats`.

## Enable the callback plugin

**Via environment variables (per-run):**

```bash
export ANSIBLE_CALLBACK_PLUGINS=/usr/share/ghostshell/ansible
export ANSIBLE_CALLBACKS_ENABLED=ghostshell
ansible-playbook site.yml
```

**Via `ansible.cfg` (persistent):**

```ini
[defaults]
callback_plugins  = /usr/share/ghostshell/ansible
callbacks_enabled = ghostshell
```

The plugin is installed at `/usr/share/ghostshell/ansible/ghostshell.py` by the deb/rpm packages.

## Browse runs

```bash
sudo ghostshell ansible list
```

```
RUN                       PLAYBOOK       CONTROLLER          OK  CHG  FAIL  STARTED              HOSTS
20260528T140300-12345     deploy.yml     ctrl.example.com     8    3     1  2026-05-28 14:03:00  web1,web2
20260527T093000-11001     baseline.yml   ctrl.example.com    24    0     0  2026-05-27 09:30:00  web1,web2,db1
```

```bash
sudo ghostshell ansible show 20260528T140300-12345
```

```
Playbook  : deploy.yml
Run ID    : 20260528T140300-12345
Controller: ctrl.example.com
User      : alice
Started   : 2026-05-28 14:03:00
Duration  : 43s

PLAY [Install web server]
  ✓  web1   install nginx           ansible.builtin.dnf       @14:03:01
  ~  web1   configure nginx         ansible.builtin.template  @14:03:04  (changed)
  ✓  web2   install nginx           ansible.builtin.dnf       @14:03:01
  ✗  web2   fail intentionally      ansible.builtin.command   @14:03:09
      rc: 1
      stderr: /usr/bin/false: intentional failure

PLAY RECAP
  web1   ok=8    changed=3   failed=0   unreachable=0   skipped=1
  web2   ok=6    changed=1   failed=1   unreachable=0   skipped=1
```

Status icons: `✓` = ok, `~` = changed, `✗` = failed, `!` = unreachable, `-` = skipped.

## Fail-open

If `ghostshell-daemon` is unreachable when the playbook runs, the run is saved locally to:

```
~/.local/share/ghostshell/ansible/<runid>.ajsonl
```

The playbook is **never aborted** due to ghostshell failures. The local file is ingested into the central store when `ghostshell-daemon` next starts.

## `no_log` tasks

Tasks with `no_log: true` are recorded with output replaced by `<censored>`:

```
  ✓  web1   rotate db password    ansible.builtin.command  @14:03:12
      stdout: <censored>
      stderr: <censored>
```

The task name, module, host, status, and rc are always recorded.

## Limitation

Only **controllers** with `ghostshell` installed produce Ansible records. Managed hosts receive raw Ansible SSH execs. If the sshd `ForceCommand` wrapper is configured on managed hosts, those execs are captured as terminal sessions — but with no task name or status, just the raw `AnsiballZ_<module>.py` invocation.
