import os
import socket

RUN_DIR = "/run/certidude"
CONFIG_DIR = "/etc/certidude"
CLIENT_CONFIG_PATH = os.path.join(CONFIG_DIR, "client.conf")

RE_FQDN = r"^(([a-z0-9]|[a-z0-9][a-z0-9\-_]*[a-z0-9])\.)+([a-z0-9]|[a-z0-9][a-z0-9\-_]*[a-z0-9])?$"
RE_HOSTNAME = r"^[a-z0-9]([a-z0-9\-_]{0,61}[a-z0-9])?$"
RE_COMMON_NAME = r"^[A-Za-z0-9\-\.\_@]+$"

FQDN = socket.getfqdn()

try:
    HOSTNAME, DOMAIN = FQDN.split(".", 1)
except ValueError:  # If FQDN is not configured
    HOSTNAME = FQDN
    DOMAIN = None

if os.path.exists("/etc/strongswan/ipsec.conf"):
    STRONGSWAN_PREFIX = "/etc/strongswan"
else:
    STRONGSWAN_PREFIX = "/etc"
