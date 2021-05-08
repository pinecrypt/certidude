# coding: utf-8

import click
import hashlib
import logging
import ipsecparse
import json
import os
import random
import re
import signal
import string
import socket
import subprocess
import sys
import requests
from asn1crypto import pem, x509
from asn1crypto.csr import CertificationRequest
from certbuilder import CertificateBuilder, pem_armor_certificate
from csrbuilder import CSRBuilder, pem_armor_csr
from configparser import ConfigParser, NoOptionError
from datetime import datetime, timedelta
from email.utils import formatdate
from oscrypto import asymmetric
from pinecrypt.client import const


def selinux_fixup(path):
    """
    Fix OpenVPN credential store security context on Fedora
    """
    if os.path.exists("/usr/bin/chcon") and os.path.exists("/sys/fs/selinux"):
        cmd = "chcon", "--type=home_cert_t", path
        subprocess.call(cmd)


class ConfigTreeParser(ConfigParser):
    def __init__(self, path, *args, **kwargs):
        ConfigParser.__init__(self, *args, **kwargs)
        if os.path.exists(path):
            with open(path) as fh:
                click.echo("Parsing: %s" % fh.name)
                self.read_file(fh)
        if os.path.exists(path + ".d"):
            for filename in os.listdir(path + ".d"):
                if not filename.endswith(".conf"):
                    continue
                with open(os.path.join(path + ".d", filename)) as fh:
                    click.echo("Parsing: %s" % fh.name)
                    self.read_file(fh)


@click.command("provision", help="Add endpoint to Certidude client config")
@click.argument("authority")
@click.option("-m", "--method", help="Force connection method")
def certidude_provision(authority, method):
    client_config = ConfigParser()
    try:
        os.makedirs(os.path.dirname(const.CLIENT_CONFIG_PATH))
    except FileExistsError:
        pass
    if os.path.exists(const.CLIENT_CONFIG_PATH):
        client_config.read_file(open(const.CLIENT_CONFIG_PATH))
    if client_config.has_section(authority):
        click.echo("Section '%s' already exists in %s, remove to regenerate" % (authority, const.CLIENT_CONFIG_PATH))
    else:
        click.echo("Section '%s' added to %s" % (authority, const.CLIENT_CONFIG_PATH))
        b = os.path.join(os.path.join(const.CONFIG_DIR, "authority", authority))
        client_config.add_section(authority)
        client_config.set(authority, "trigger", "interface up")
        client_config.set(authority, "common name", "$HOSTNAME")
        client_config.set(authority, "request path", os.path.join(b, "host_req.pem"))
        client_config.set(authority, "key path", os.path.join(b, "host_key.pem"))
        client_config.set(authority, "certificate path", os.path.join(b, "host_cert.pem"))
        client_config.set(authority, "authority path",  os.path.join(b, "ca_cert.pem"))
        if method:
            client_config.set(authority, "method", method)
        with open(const.CLIENT_CONFIG_PATH + ".part", 'w') as fh:
            client_config.write(fh)
        os.rename(const.CLIENT_CONFIG_PATH + ".part", const.CLIENT_CONFIG_PATH)
    os.system("certidude enroll")

@click.command("enroll", help="Run processes for requesting certificates and configuring services")
@click.option("-k", "--kerberos", default=False, is_flag=True, help="Offer system keytab for auth")
@click.option("-f", "--fork", default=False, is_flag=True, help="Fork to background")
@click.option("-nw", "--no-wait", default=False, is_flag=True, help="Return immediately if server doesn't autosign")

def certidude_enroll(fork, no_wait, kerberos):
    try:
        os.makedirs(const.RUN_DIR)
    except FileExistsError:
        pass

    if not os.path.exists(const.CLIENT_CONFIG_PATH):
        click.echo("Client not configured, so not going to enroll")
        return

    clients = ConfigTreeParser(const.CLIENT_CONFIG_PATH)

    for authority_name in clients.sections():
        try:
            trigger = clients.get(authority_name, "trigger")
        except NoOptionError:
            trigger = "interface up"

        if trigger == "domain joined":
            # Stop further processing if command line argument said so or trigger expects domain membership
            if not os.path.exists("/etc/krb5.keytab"):
                continue
            kerberos = True
        elif trigger == "interface up":
            pass
        else:
            raise


        #########################
        ### Fork if requested ###
        #########################

        pid_path = os.path.join(const.RUN_DIR, authority_name + ".pid")

        try:
            with open(pid_path) as fh:
                pid = int(fh.readline())
                os.kill(pid, signal.SIGTERM)
                click.echo("Terminated process %d" % pid)
            os.unlink(pid_path)
        except EnvironmentError:
            pass

        if fork:
            child_pid = os.fork()
        else:
            child_pid = None

        if child_pid:
            click.echo("Spawned certificate request process with PID %d" % (child_pid))
            continue

        with open(pid_path, "w") as fh:
            fh.write("%d\n" % os.getpid())

        try:
            authority_path = clients.get(authority_name, "authority path")
        except NoOptionError:
            authority_path = "/etc/certidude/authority/%s/ca_cert.pem" % authority_name

        if os.path.exists(authority_path):
            click.echo("Found authority certificate in: %s" % authority_path)
            with open(authority_path, "rb") as fh:
                header, _, certificate_der_bytes = pem.unarmor(fh.read())
                authority_certificate = x509.Certificate.load(certificate_der_bytes)
        else:
            if not os.path.exists(os.path.dirname(authority_path)):
                os.makedirs(os.path.dirname(authority_path))
            authority_url = "http://%s/api/certificate/" % authority_name
            click.echo("Attempting to fetch authority certificate from %s" % authority_url)
            try:
                r = requests.get(authority_url,
                    headers={"Accept": "application/x-x509-ca-cert,application/x-pem-file"})
                header, _, certificate_der_bytes = pem.unarmor(r.content)
                authority_certificate = x509.Certificate.load(certificate_der_bytes)
            except requests.exceptions.ConnectionError:
                click.echo("Connection error while attempting to fetch %s" % authority_url)
                continue
            authority_partial = authority_path + ".part"
            with open(authority_partial, "wb") as oh:
                oh.write(r.content)
            click.echo("Writing authority certificate to: %s" % authority_path)
            selinux_fixup(authority_partial)
            os.rename(authority_partial, authority_path)

        authority_public_key = asymmetric.load_public_key(
            authority_certificate["tbs_certificate"]["subject_public_key_info"])

        try:
            config_path = clients.get(authority_name, "config path")
        except NoOptionError:
            config_path = "/etc/certidude/authority/%s/config.json" % authority_name

        if os.path.exists(config_path):
            click.echo("Found config in: %s" % config_path)
            with open(config_path) as fh:
                bootstrap = json.loads(fh.read())
        else:
            bootstrap_url = "http://%s/api/bootstrap/" % authority_name
            click.echo("Attempting to bootstrap connection from %s" % bootstrap_url)
            try:
                r = requests.get(bootstrap_url)
            except requests.exceptions.ConnectionError:
                click.echo("Connection error while attempting to fetch %s" % bootstrap_url)
                continue
            else:
                if r.status_code != 200:
                    raise ValueError("Bootstrap API endpoint returned %s" % r.content)
            bootstrap = r.json()

            config_partial = config_path + ".part"
            with open(config_partial, "wb") as oh:
                oh.write(r.content)
            click.echo("Writing configuration to: %s" % config_path)
            os.rename(config_partial, config_path)

        try:
            common_name = clients.get(authority_name, "common name")
        except NoOptionError:
            click.echo("No common name specified for %s, not requesting a certificate" % authority_name)
            continue

        # If deriving common name from *current* hostname is preferred
        if common_name == "$HOSTNAME":
            common_name = const.HOSTNAME
        elif common_name == "$FQDN":
            common_name = const.FQDN
        elif "$" in common_name:
            raise ValueError("Invalid variable '%s' supplied, only $HOSTNAME and $FQDN allowed" % common_name)
        if not re.match(const.RE_COMMON_NAME, common_name):
            raise ValueError("Supplied common name %s doesn't match the expression %s" % (common_name, const.RE_COMMON_NAME))


        ################################
        ### Generate keypair and CSR ###
        ################################

        try:
            key_path = clients.get(authority_name, "key path")
            request_path = clients.get(authority_name, "request path")
        except NoOptionError:
            key_path = "/etc/certidude/authority/%s/host_key.pem" % authority_name
            request_path = "/etc/certidude/authority/%s/host_csr.pem" % authority_name

        if os.path.exists(request_path):
            with open(request_path, "rb") as fh:
                header, _, der_bytes = pem.unarmor(fh.read())
                csr = CertificationRequest.load(der_bytes)
                if csr["certification_request_info"]["subject"].native["common_name"] != common_name:
                    click.echo("Stored request's common name differs from currently requested one, deleting old request")
                    os.remove(request_path)

        if not os.path.exists(request_path):
            key_partial = key_path + ".part"
            request_partial = request_path + ".part"

            if authority_public_key.algorithm == "ec":
                self_public_key, private_key = asymmetric.generate_pair("ec", curve=authority_public_key.curve)
            elif authority_public_key.algorithm == "rsa":
                self_public_key, private_key = asymmetric.generate_pair("rsa", bit_size=authority_public_key.bit_size)
            else:
                NotImplemented

            builder = CSRBuilder({"common_name": common_name}, self_public_key)
            request = builder.build(private_key)
            with open(key_partial, 'wb') as f:
                f.write(asymmetric.dump_private_key(private_key, None))
            with open(request_partial, 'wb') as f:
                f.write(pem_armor_csr(request))
            selinux_fixup(key_partial)
            selinux_fixup(request_partial)
            os.rename(key_partial, key_path)
            os.rename(request_partial, request_path)


        ##############################################
        ### Submit CSR and save signed certificate ###
        ##############################################

        try:
            certificate_path = clients.get(authority_name, "certificate path")
        except NoOptionError:
            certificate_path = "/etc/certidude/authority/%s/host_cert.pem" % authority_name

        try:
            autosign = clients.getboolean(authority_name, "autosign")
        except NoOptionError:
            autosign = True

        if not os.path.exists(certificate_path):
            # Set up URL-s
            request_params = set()
            request_params.add("autosign=%s" % ("yes" if autosign else "no"))
            if not no_wait:
                request_params.add("wait=forever")

            kwargs = {
                "data": open(request_path),
                "verify": authority_path,
                "headers": {
                    "Content-Type": "application/pkcs10",
                    "Accept": "application/x-x509-user-cert,application/x-pem-file",
                    "Date": formatdate(usegmt=True),
                }
            }

            # If machine is joined to domain attempt to present machine credentials for authentication
            if kerberos:
                try:
                    from requests_kerberos import HTTPKerberosAuth, OPTIONAL
                except ImportError:
                    click.echo("Kerberos bindings not available, please install requests-kerberos")
                else:
                    os.environ["KRB5CCNAME"]="/tmp/ca.ticket"

                    # Mac OS X has keytab with lowercase hostname
                    cmd = "kinit -S HTTP/%s -k %s$" % (authority_name, const.HOSTNAME.lower())
                    click.echo("Executing: %s" % cmd)
                    if os.system(cmd):
                        # Fedora /w SSSD has keytab with uppercase hostname
                        cmd = "kinit -S HTTP/%s -k %s$" % (authority_name, const.HOSTNAME.upper())
                        if os.system(cmd):
                            # Failed, probably /etc/krb5.keytab contains spaghetti
                            raise ValueError("Failed to initialize Kerberos service ticket using machine keytab")
                    assert os.path.exists("/tmp/ca.ticket"), "Ticket not created!"
                    click.echo("Initialized Kerberos service ticket using machine keytab")
                    kwargs["auth"] = HTTPKerberosAuth(mutual_authentication=OPTIONAL, force_preemptive=True)
            else:
                click.echo("Not using machine keytab")

            request_url = "https://%s:8443/api/request/" % authority_name
            if request_params:
                request_url = request_url + "?" + "&".join(request_params)

            try:
                submission = requests.post(request_url, **kwargs)
            except requests.exceptions.ConnectionError:
                click.echo("Connection error while attempting to submit request to %s" % request_url)
                continue

            # Destroy service ticket
            if os.path.exists("/tmp/ca.ticket"):
                os.system("kdestroy")

            if submission.status_code == requests.codes.ok:
                pass
            if submission.status_code == requests.codes.accepted:
                click.echo("Server accepted the request, but refused to sign immediately (%s). Waiting was not requested, hence quitting for now" % submission.text)
                os.unlink(pid_path)
                continue
            if submission.status_code == requests.codes.conflict:
                raise errors.DuplicateCommonNameError("Different signing request with same CN is already present on server, server refuses to overwrite")
            elif submission.status_code == requests.codes.gone:
                # Should the client retry or disable request submission?
                raise ValueError("Server refused to sign the request") # TODO: Raise proper exception
            elif submission.status_code == requests.codes.bad_request:
                raise ValueError("Server said following, likely current certificate expired/revoked? %s" % submission.text)
            else:
                submission.raise_for_status()

            try:
                header, _, certificate_der_bytes = pem.unarmor(submission.content)
                cert = x509.Certificate.load(certificate_der_bytes)
            except: # TODO: catch correct exceptions
                raise ValueError("Failed to parse PEM: %s" % submission.text)

            os.umask(0o022)
            certificate_partial = certificate_path + ".part"
            with open(certificate_partial, "w") as fh:
                # Dump certificate
                fh.write(submission.text)

            click.echo("Writing certificate to: %s" % certificate_path)
            selinux_fixup(certificate_partial)
            os.rename(certificate_partial, certificate_path)

        else:
            click.echo("Certificate found at %s and no renewal requested" % certificate_path)


        ##################################
        ### Configure related services ###
        ##################################

        endpoint = authority_name

        try:
            method = clients.get(authority_name, "method")
        except NoOptionError:
            method = "init/openvpn"

        click.echo("Configuring '%s'" % endpoint)
        csummer = hashlib.sha1()
        csummer.update(endpoint.encode("ascii"))
        csum = csummer.hexdigest()
        uuid = csum[:8] + "-" + csum[8:12] + "-" + csum[12:16] + "-" + csum[16:20] + "-" + csum[20:32]

        # OpenVPN set up with initscripts
        if method == "init/openvpn":
            openvpn_config_path = "/etc/openvpn/%s.conf" % endpoint
            with open(openvpn_config_path + ".part", "w") as fh:
                fh.write("client\n")
                fh.write("nobind\n")
                fh.write("remote %s 1194 udp\n" % endpoint)
                fh.write("remote %s 443 tcp\n" % endpoint)
                fh.write("tls-version-min %s\n" % bootstrap["openvpn"]["tls_version_min"])
                if bootstrap["openvpn"]["tls_version_min"] == "1.3":
                    fh.write("tls-ciphersuites %s\n" % bootstrap["openvpn"]["tls_ciphersuites"])
                elif bootstrap["openvpn"]["tls_version_min"] == "1.2":
                    fh.write("tls-cipher %s\n" % bootstrap["openvpn"]["tls_cipher"])
                else:
                    raise NotImplementedError("Unsupported TLS version")
                fh.write("ncp-disable\n")
                fh.write("cipher %s\n" % bootstrap["openvpn"]["cipher"])
                fh.write("auth %s\n" % bootstrap["openvpn"]["auth"])
                fh.write("mute-replay-warnings\n")
                fh.write("reneg-sec 0\n")
                fh.write("remote-cert-tls server\n")
                fh.write("dev tun\n")
                fh.write("persist-tun\n")
                fh.write("persist-key\n")
                fh.write("ca %s\n" % authority_path)
                fh.write("key %s\n" % key_path)
                fh.write("cert %s\n" % certificate_path)
            os.rename(openvpn_config_path + ".part", openvpn_config_path)
            if os.path.exists("/bin/systemctl"):
                click.echo("Re-running systemd generators for OpenVPN...")
                os.system("systemctl daemon-reload")
#            if not os.path.exists("/etc/systemd/system/openvpn-reconnect.service"):
#                with open("/etc/systemd/system/openvpn-reconnect.service.part", "w") as fh:
#                    fh.write(env.get_template("client/openvpn-reconnect.service").render(context))
#                os.rename("/etc/systemd/system/openvpn-reconnect.service.part",
#                    "/etc/systemd/system/openvpn-reconnect.service")
#                click.echo("Created /etc/systemd/system/openvpn-reconnect.service")
                os.system("systemctl restart openvpn")
            continue

        # IPSec set up with initscripts
        if method == "init/strongswan":
            strongswan_config_path = os.path.join(const.STRONGSWAN_PREFIX, "ipsec.conf")
            strongswan_secrets_path = os.path.join(const.STRONGSWAN_PREFIX, "ipsec.secrets")
            with open(strongswan_config_path) as fh:
                config = ipsecparse.loads(fh.read())
            config["ca", endpoint] = {}
            config["ca", endpoint]["cacert"] = authority_path
            config["ca", endpoint]["auto"] = "add"
            config["conn", endpoint] = {}
            config["conn", endpoint]["auto"] = "start"
            config["conn", endpoint]["right"] = endpoint
            config["conn", endpoint]["keyingtries"] = "%forever"
            config["conn", endpoint]["dpdaction"] = "restart"
            config["conn", endpoint]["closeaction"] = "restart"
            config["conn", endpoint]["rightsubnet"] = "0.0.0.0/0"
            config["conn", endpoint]["ike"] = "%s!" % bootstrap["strongswan"]["ike"]
            config["conn", endpoint]["esp"] = "%s!" % bootstrap["strongswan"]["esp"]
            config["conn", endpoint]["leftsourceip"] = "%config"
            config["conn", endpoint]["leftcert"] = certificate_path
#    leftca="$AUTHORITY_CERTIFICATE_DISTINGUISHED_NAME"
#    rightca="$AUTHORITY_CERTIFICATE_DISTINGUISHED_NAME"


            with open(strongswan_secrets_path + ".part", "w") as fh:
                fh.write(": %s %s\n" % (
                  "ECDSA" if authority_public_key.algorithm == "ec" else "RSA",
                  key_path
                ))

            with open(strongswan_config_path + ".part", "w") as fh:
                fh.write(config.dumps())
            os.rename(strongswan_secrets_path + ".part", strongswan_secrets_path)
            os.rename(strongswan_config_path + ".part", strongswan_config_path)

            # Tune AppArmor profile, TODO: retain contents
            if os.path.exists("/etc/apparmor.d/local"):
                with open("/etc/apparmor.d/local/usr.lib.ipsec.charon", "w") as fh:
                    fh.write(key_path + " r,\n")
                    fh.write(authority_path + " r,\n")
                    fh.write(certificate_path + " r,\n")

            # Attempt to reload config or start if it's not running
            if os.path.exists("/usr/sbin/strongswan"): # wtf fedora
                if os.system("strongswan update"):
                    os.system("strongswan start")
            else:
                if os.system("ipsec update"):
                    os.system("ipsec start")

            continue

        # OpenVPN set up with NetworkManager
        if method == "network-manager/openvpn":
            # NetworkManager-strongswan-gnome
            nm_config_path = os.path.join("/etc/NetworkManager/system-connections", endpoint)
            if os.path.exists(nm_config_path):
                click.echo("Not creating %s, remove to regenerate" % nm_config_path)
                continue
            nm_config = ConfigParser()
            nm_config.add_section("connection")
            nm_config.set("connection", "certidude managed", "true")
            nm_config.set("connection", "id", endpoint)
            nm_config.set("connection", "uuid", uuid)
            nm_config.set("connection", "type", "vpn")
            nm_config.add_section("vpn")
            nm_config.set("vpn", "service-type", "org.freedesktop.NetworkManager.openvpn")
            nm_config.set("vpn", "connection-type", "tls")
            nm_config.set("vpn", "comp-lzo", "no")
            nm_config.set("vpn", "cert-pass-flags", "0")
            nm_config.set("vpn", "tap-dev", "no")
            nm_config.set("vpn", "remote-cert-tls", "server") # Assert TLS Server flag of X.509 certificate
            nm_config.set("vpn", "remote", endpoint)
            nm_config.set("vpn", "key", key_path)
            nm_config.set("vpn", "cert", certificate_path)
            nm_config.set("vpn", "ca", authority_path)
            nm_config.set("vpn", "tls-cipher", bootstrap["openvpn"]["tls_cipher"])
            nm_config.set("vpn", "cipher", bootstrap["openvpn"]["cipher"])
            nm_config.set("vpn", "auth", bootstrap["openvpn"]["auth"])
            nm_config.add_section("ipv4")
            nm_config.set("ipv4", "method", "auto")
            nm_config.set("ipv4", "never-default", "true")
            nm_config.add_section("ipv6")
            nm_config.set("ipv6", "method", "auto")
            nm_config.set("vpn", "port", "443")
            nm_config.set("vpn", "proto-tcp", "yes")

            # Prevent creation of files with liberal permissions
            os.umask(0o177)

            # Write NetworkManager configuration
            with open(nm_config_path, "w") as fh:
                nm_config.write(fh)
                click.echo("Created %s" % nm_config_path)
            if os.path.exists("/run/NetworkManager"):
                os.system("nmcli con reload")
                os.system("nmcli con up %s" % uuid)
            continue


        # IPSec set up with NetworkManager
        if method == "network-manager/strongswan":
            client_config = ConfigParser()
            nm_config = ConfigParser()
            nm_config.add_section("connection")
            nm_config.set("connection", "certidude managed", "true")
            nm_config.set("connection", "id", endpoint)
            nm_config.set("connection", "uuid", uuid)
            nm_config.set("connection", "type", "vpn")
            nm_config.add_section("vpn")
            nm_config.set("vpn", "service-type", "org.freedesktop.NetworkManager.strongswan")
            nm_config.set("vpn", "encap", "no")
            nm_config.set("vpn", "virtual", "yes")
            nm_config.set("vpn", "method", "key")
            nm_config.set("vpn", "ipcomp", "no")
            nm_config.set("vpn", "address", endpoint)
            nm_config.set("vpn", "userkey", key_path)
            nm_config.set("vpn", "usercert", certificate_path)
            nm_config.set("vpn", "certificate", authority_path)
            nm_config.set("vpn", "ike", bootstrap["strongswan"]["ike"])
            nm_config.set("vpn", "esp", bootstrap["strongswan"]["esp"])
            nm_config.set("vpn", "proposal", "yes")

            nm_config.add_section("ipv4")
            nm_config.set("ipv4", "method", "auto")

            # Prevent creation of files with liberal permissions
            os.umask(0o177)

            # Write NetworkManager configuration
            with open(os.path.join("/etc/NetworkManager/system-connections", endpoint), "w") as fh:
                nm_config.write(fh)
                click.echo("Created %s" % fh.name)
            if os.path.exists("/run/NetworkManager"):
                os.system("nmcli con reload")
                os.system("nmcli con up %s" % uuid)
            continue

        click.echo("Unknown service: %s" % service_config.get(endpoint, "service"))
        os.unlink(pid_path)


@click.group()
def entry_point(): pass


entry_point.add_command(certidude_enroll)
entry_point.add_command(certidude_provision)

if __name__ == "__main__":
    entry_point()
