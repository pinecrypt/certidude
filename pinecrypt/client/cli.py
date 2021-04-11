# coding: utf-8

import click
import hashlib
import logging
import os
import random
import re
import signal
import string
import socket
import subprocess
import sys
import requests
from ipsecparse import loads
from asn1crypto import pem, x509
from asn1crypto.csr import CertificationRequest
from certbuilder import CertificateBuilder, pem_armor_certificate
from csrbuilder import CSRBuilder, pem_armor_csr
from configparser import ConfigParser, NoOptionError
from datetime import datetime, timedelta
from oscrypto import asymmetric
from pinecrypt.client import const

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
def certidude_provision(authority):
    client_config = ConfigParser()
    os.makedirs(os.path.dirname(const.CLIENT_CONFIG_PATH))
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
        with open(const.CLIENT_CONFIG_PATH + ".part", 'w') as fh:
            client_config.write(fh)
        os.rename(const.CLIENT_CONFIG_PATH + ".part", const.CLIENT_CONFIG_PATH)
    os.system("certidude enroll")

@click.command("enroll", help="Run processes for requesting certificates and configuring services")
@click.option("-k", "--kerberos", default=False, is_flag=True, help="Offer system keytab for auth")
@click.option("-f", "--fork", default=False, is_flag=True, help="Fork to background")
@click.option("-nw", "--no-wait", default=False, is_flag=True, help="Return immideately if server doesn't autosign")
def certidude_enroll(fork, no_wait, kerberos):
    try:
        os.makedirs(const.RUN_DIR)
    except FileExistsError:
        pass

    context = globals()
    context.update(locals())

    if not os.path.exists(const.CLIENT_CONFIG_PATH):
        click.echo("Client not configured, so not going to enroll")
        return

    clients = ConfigTreeParser(const.CLIENT_CONFIG_PATH)
    service_config = ConfigTreeParser(const.SERVICES_CONFIG_PATH)

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
        finally:
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
                except: # TODO: catch correct exceptions
                    raise
                #    raise ValueError("Failed to parse PEM: %s" % r.text)
                authority_partial = authority_path + ".part"
                with open(authority_partial, "wb") as oh:
                    oh.write(r.content)
                click.echo("Writing authority certificate to: %s" % authority_path)
                selinux_fixup(authority_partial)
                os.rename(authority_partial, authority_path)

            authority_public_key = asymmetric.load_public_key(
                authority_certificate["tbs_certificate"]["subject_public_key_info"])



        # Attempt to install CA certificates system wide
        try:
            authority_system_wide = clients.getboolean(authority_name, "system wide")
        except NoOptionError:
            authority_system_wide = False
        finally:
            if authority_system_wide:
                # Firefox, Chromium, wget, curl on Fedora
                # Note that if ~/.pki/nssdb has been customized before, curl breaks
                if os.path.exists("/usr/bin/update-ca-trust"):
                    link_path = "/etc/pki/ca-trust/source/anchors/%s" % authority_name
                    if not os.path.lexists(link_path):
                        os.symlink(authority_path, link_path)
                    os.system("update-ca-trust")

                # curl on Fedora ?
                # pip

                # Firefox (?) on Debian, Ubuntu
                if os.path.exists("/usr/bin/update-ca-certificates") or os.path.exists("/usr/sbin/update-ca-certificates"):
                    link_path = "/usr/local/share/ca-certificates/%s" % authority_name
                    if not os.path.lexists(link_path):
                        os.symlink(authority_path, link_path)
                    os.system("update-ca-certificates")

                # TODO: test for curl, wget

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
                    "Accept": "application/x-x509-user-cert,application/x-pem-file"
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
            submission = requests.post(request_url, **kwargs)

            # Destroy service ticket
            if os.path.exists("/tmp/ca.ticket"):
                os.system("kdestroy")

            if submission.status_code == requests.codes.ok:
                pass
            if submission.status_code == requests.codes.accepted:
                click.echo("Server accepted the request, but refused to sign immideately (%s). Waiting was not requested, hence quitting for now" % submission.text)
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

            assert cert.subject.native["common_name"] == common_name, \
                "Expected certificate with common name %s, but got %s instead" % \
                    (common_name, cert.subject.native["common_name"])

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

        for endpoint in service_config.sections():
            if service_config.get(endpoint, "authority") != authority_name:
                continue

            click.echo("Configuring '%s'" % endpoint)
            csummer = hashlib.sha1()
            csummer.update(endpoint.encode("ascii"))
            csum = csummer.hexdigest()
            uuid = csum[:8] + "-" + csum[8:12] + "-" + csum[12:16] + "-" + csum[16:20] + "-" + csum[20:32]

            # Intranet HTTPS handled by PKCS#12 bundle generation,
            # so it will not be implemented here

            # OpenVPN set up with initscripts
            if service_config.get(endpoint, "service") == "init/openvpn":
                if os.path.exists("/etc/openvpn/%s.disabled" % endpoint) and not os.path.exists("/etc/openvpn/%s.conf" % endpoint):
                    os.rename("/etc/openvpn/%s.disabled" % endpoint, "/etc/openvpn/%s.conf" % endpoint)
                if os.path.exists("/bin/systemctl"):
                    click.echo("Re-running systemd generators for OpenVPN...")
                    os.system("systemctl daemon-reload")
                if not os.path.exists("/etc/systemd/system/openvpn-reconnect.service"):
                    with open("/etc/systemd/system/openvpn-reconnect.service.part", "w") as fh:
                        fh.write(env.get_template("client/openvpn-reconnect.service").render(context))
                    os.rename("/etc/systemd/system/openvpn-reconnect.service.part",
                        "/etc/systemd/system/openvpn-reconnect.service")
                    click.echo("Created /etc/systemd/system/openvpn-reconnect.service")
                click.echo("Starting OpenVPN...")
                os.system("service openvpn start")
                continue

            # IPSec set up with initscripts
            if service_config.get(endpoint, "service") == "init/strongswan":
                config = loads(open("%s/ipsec.conf" % const.STRONGSWAN_PREFIX).read())
                for section_type, section_name in config:
                    # Identify correct ipsec.conf section by leftcert
                    if section_type != "conn":
                        continue
                    if config[section_type,section_name]["leftcert"] != certificate_path:
                        continue

                    if config[section_type,section_name].get("left", "") == "%defaultroute":
                        config[section_type,section_name]["auto"] = "start" # This is client
                    elif config[section_type,section_name].get("leftsourceip", ""):
                        config[section_type,section_name]["auto"] = "add" # This is server
                    else:
                        config[section_type,section_name]["auto"] = "route" # This is site-to-site tunnel

                    with open("%s/ipsec.conf.part" % const.STRONGSWAN_PREFIX, "w") as fh:
                        fh.write(config.dumps())
                    os.rename(
                        "%s/ipsec.conf.part" % const.STRONGSWAN_PREFIX,
                        "%s/ipsec.conf" % const.STRONGSWAN_PREFIX)
                    break

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
            if service_config.get(endpoint, "service") == "network-manager/openvpn":
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
                nm_config.set("vpn", "remote", service_config.get(endpoint, "remote"))
                nm_config.set("vpn", "key", key_path)
                nm_config.set("vpn", "cert", certificate_path)
                nm_config.set("vpn", "ca", authority_path)
                nm_config.set("vpn", "tls-cipher", "TLS-%s-WITH-AES-256-GCM-SHA384" % (
                    "ECDHE-ECDSA" if authority_public_key.algorithm == "ec" else "DHE-RSA"))
                nm_config.set("vpn", "cipher", "AES-128-GCM")
                nm_config.set("vpn", "auth", "SHA384")
                nm_config.add_section("ipv4")
                nm_config.set("ipv4", "method", "auto")
                nm_config.set("ipv4", "never-default", "true")
                nm_config.add_section("ipv6")
                nm_config.set("ipv6", "method", "auto")

                try:
                    nm_config.set("vpn", "port", str(service_config.getint(endpoint, "port")))
                except NoOptionError:
                    nm_config.set("vpn", "port", "1194")

                try:
                    if service_config.get(endpoint, "proto") == "tcp":
                        nm_config.set("vpn", "proto-tcp", "yes")
                except NoOptionError:
                    pass

                # Prevent creation of files with liberal permissions
                os.umask(0o177)

                # Write NetworkManager configuration
                with open(nm_config_path, "w") as fh:
                    nm_config.write(fh)
                    click.echo("Created %s" % nm_config_path)
                if os.path.exists("/run/NetworkManager"):
                    os.system("nmcli con reload")
                continue


            # IPSec set up with NetworkManager
            if service_config.get(endpoint, "service") == "network-manager/strongswan":
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
                nm_config.set("vpn", "address", service_config.get(endpoint, "remote"))
                nm_config.set("vpn", "userkey", key_path)
                nm_config.set("vpn", "usercert", certificate_path)
                nm_config.set("vpn", "certificate", authority_path)
                dhgroup = "ecp384" if authority_public_key.algorithm == "ec" else "modp2048"
                nm_config.set("vpn", "ike", "aes256-sha384-prfsha384-" + dhgroup)
                nm_config.set("vpn", "esp", "aes128gcm16-aes128gmac-" + dhgroup)
                nm_config.set("vpn", "proposal", "yes")

                nm_config.add_section("ipv4")
                nm_config.set("ipv4", "method", "auto")

                # Add routes, may need some more tweaking
                if service_config.has_option(endpoint, "route"):
                    for index, subnet in enumerate(service_config.get(endpoint, "route").split(","), start=1):
                        nm_config.set("ipv4", "route%d" % index, subnet)

                # Prevent creation of files with liberal permissions
                os.umask(0o177)

                # Write NetworkManager configuration
                with open(os.path.join("/etc/NetworkManager/system-connections", endpoint), "w") as fh:
                    nm_config.write(fh)
                    click.echo("Created %s" % fh.name)
                if os.path.exists("/run/NetworkManager"):
                    os.system("nmcli con reload")
                continue

            # TODO: Puppet, OpenLDAP, <insert awesomeness here>
            click.echo("Unknown service: %s" % service_config.get(endpoint, "service"))
        os.unlink(pid_path)


@click.group()
def entry_point(): pass


entry_point.add_command(certidude_enroll)
entry_point.add_command(certidude_provision)

if __name__ == "__main__":
    entry_point()
