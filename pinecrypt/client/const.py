import os
import socket

RUN_DIR = "/run/certidude"
CONFIG_DIR = "/etc/certidude"
CLIENT_CONFIG_PATH = os.path.join(CONFIG_DIR, "client.conf")
SERVICES_CONFIG_PATH = os.path.join(CONFIG_DIR, "services.conf")

RE_FQDN =  "^(([a-z0-9]|[a-z0-9][a-z0-9\-_]*[a-z0-9])\.)+([a-z0-9]|[a-z0-9][a-z0-9\-_]*[a-z0-9])?$"
RE_HOSTNAME =  "^[a-z0-9]([a-z0-9\-_]{0,61}[a-z0-9])?$"
RE_COMMON_NAME = "^[A-Za-z0-9\-\.\_@]+$"

try:
    FQDN = socket.getaddrinfo(socket.gethostname(), 0, socket.AF_INET, 0, 0, socket.AI_CANONNAME)[0][3]
except socket.gaierror:
    FQDN = socket.gethostname()

try:
    HOSTNAME, DOMAIN = FQDN.split(".", 1)
except ValueError: # If FQDN is not configured
    HOSTNAME = FQDN
    DOMAIN = None
