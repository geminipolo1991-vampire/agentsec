# Single-EC2 AgentSec deployment

This deployment targets an existing Amazon Linux 2023 EC2 instance. It runs
the AgentSec backend, token-owning UI bridge, and production UI as separate
systemd services on loopback. Nginx is the only public listener, on TCP 8000.

Persistent SQLite databases live in `/var/lib/agentsec`. Generated internal
secrets live in `/etc/agentsec/runtime.env` with root and `agentsec` group read
access. The installer deliberately refuses an environment containing populated
OpenAI or Anthropic API keys; those providers are enabled in a later governed
deployment.

The installer must run from a versioned directory below
`/opt/agentsec/releases`. It installs supported Amazon Linux packages, creates a
Python 3.12 virtual environment, performs a locked npm install and production
UI build, switches `/opt/agentsec/current` atomically, installs the service
units and Nginx route, and verifies all loopback health endpoints.

After installation, verify the public route from an allowed client:

```bash
deploy/ec2-single/verify.sh http://EC2_PUBLIC_IP:8000 http://EC2_PUBLIC_IP:8000
```

Useful operations:

```bash
sudo systemctl status agentsec-backend agentsec-bridge agentsec-ui nginx
sudo journalctl -u agentsec-backend -u agentsec-bridge -u agentsec-ui --since today
```
