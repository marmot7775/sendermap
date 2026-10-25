# Deploy

The sendermap.dev website runs on one droplet behind Cloudflare. These
files are copies of the live ones, so a rebuild starts from what runs
today. Edit the live file, then copy it back here.

| File | Goes to |
| --- | --- |
| `sendermap.service` | `/etc/systemd/system/sendermap.service` |
| `sendermap-upgrade` | `/home/marmot7/bin/sendermap-upgrade` |
| `nginx-sendermap` | `/etc/nginx/sites-available/sendermap`, enabled by a symlink from `/etc/nginx/sites-enabled/sendermap` |

The app runs from the virtualenv at `/home/marmot7/sendermap-venv` as
user `marmot7`, on 127.0.0.1:8001. nginx terminates TLS and proxies to it.

## Not in the repo

- The Cloudflare origin certificate and key. nginx reads them from
  `/etc/ssl/sendermap-cert.pem` and `/etc/ssl/sendermap-key.pem`.
- The `noip` access log format. It is defined in the dns-audit site
  file, which nginx reads first. A server without dns-audit needs that
  `log_format` added before this site loads.

## Install or upgrade

A release upgrades the site by itself: the publish workflow's deploy job
connects with a key whose `authorized_keys` line is
`command="/home/marmot7/bin/sendermap-upgrade",restrict`, so it can run
that script and nothing else, and passes the tag's version. To upgrade
by hand, run the script with a version, or:

```sh
/home/marmot7/sendermap-venv/bin/pip install --no-cache-dir --upgrade 'sendermap[web]==X.Y.Z'
sudo systemctl restart sendermap
```

Use `--no-cache-dir`. Right after a release, pip on the droplet can
resolve from a stale cached index and report "No matching distribution"
for a version that is already on PyPI.

After changing a file:

```sh
sudo systemctl daemon-reload && sudo systemctl restart sendermap   # unit
sudo nginx -t && sudo systemctl reload nginx                       # site
```
