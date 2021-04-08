from subprocess import Popen, PIPE
from pathlib import Path
from shutil import rmtree, copyfile
from tempfile import NamedTemporaryFile
import dbus

import binascii
import string
import random

import n4d

class Kerberos:

    KDCPATH = Path('/etc/krb5kdc')
    ACLPATH = KDCPATH.joinpath('kadm5.acl')
    KDCCONFPATH = KDCPATH.joinpath('kdc.conf')
    KERBEROS_PASSWORD = Path('/etc/lliurex-secrets/passgen/krb5')
    KDCCONFTEMPLATE = Path('/usr/share/krb5-kdc/kdc.conf.template')
    TEMPLATES_PATH = Path('/usr/share/n4d/templates/kerberos')
    
    # N4D Errors code

    ERROR_REALM_NOT_CREATED=-10

    def __init__(self):
        self.core = n4d.server.core.Core.get_core()
        self.systembus = dbus.SystemBus()
        systemd1 = self.systembus.get_object('org.freedesktop.systemd1','/org/freedesktop/systemd1')
        self.systemd_manager = dbus.Interface(systemd1, 'org.freedesktop.systemd1.Manager')
        # ficheros a controlar
        # /etc/krb5.conf
        
        # /etc/krb5kdc/kadm5.acl
        # /etc/krb5kdc/kdc.conf
        
        # /etc/idmapd.conf
        # /etc/default/nfs-kernel-server
        # /etc/default/nfs-common
        # /var/lib/dnsmasq/hosts/reg
        # /etc/exports.d/
        # servicio sssd

    def init_realm(self):
        realm_name = "MA6.LLIUREX.NET"
        self.core.set_variable("KERBEROS_REALM", realm_name )
        
        # Crear el fichero krb5.conf
        
        # Generate kdc config and folders
        Kerberos.KDCPATH.mkdir(0o700,parents=True, exist_ok=True)
        with Kerberos.KDCCONFTEMPLATE.open("r", encoding="utf-8") as fd:
            text = fd.read()
            text = text.replace("@MYREALM", realm_name)
        with Kerberos.KDCCONFPATH.open("w", encoding="utf-8") as fd:
            fd.write(text)
        
        # Random password to kerberos database and save
        Kerberos.KERBEROS_PASSWORD.parent.mkdir(parents=True,exist_ok=True)
        krb_passwd = self.generate_random_password()
        with Kerberos.KERBEROS_PASSWORD.open("w",encoding="utf-8") as fd:
            fd.write(krb_passwd + "\n")
        
        # Create kerberos database
        p = Popen("kdb5_util -P {password} create -s".format(password=krb_passwd), shell=True, stdout=PIPE, stderr=PIPE)
        output, error = p.communicate()
        if p.returncode != 0 :
            return n4d.responses.build_failed_call_response(self.parse_error_code(output,error))
        
        # Create acls to read keytabs from clients
        self.set_kadm5_acl()

        # Restart services
        self.systemd_manager.RestartUnit("krb5-kdc.service","replace")
        self.systemd_manager.RestartUnit("krb5-admin-server.service","replace")
        
        return n4d.responses.build_successful_call_response(True)
    #def init_realm


    def get_user_keytab(self, ip, user):
        # Check if user exists on kerberos database
        p = Popen( "kadmin.local -q 'getprinc {user}'".format(user=user), shell=True, stdout=PIPE, stderr=PIPE )
        output, error = p.communicate()
        if p.returncode != 0:
            return n4d.responses.build_failed_call_response( self.parse_error_code( output, error ) )

        # If not exists addprinc to database with randkey
        if len(error) > 0 and 'not exist' in error.decode('utf-8'):
            p = Popen("kadmin.local -q 'addprinc -randkey {user}'".format(user=user),stdout=PIPE,stderr=PIPE)
            output, error = p.communicate()
            if p.returncode != 0:
                return n4d.responses.build_unhandled_error_response(tback_txt=error)
        
        # Create temporal keytab with user princ
        temporal_keytab = NamedTemporaryFile(mode='r+b', delete=False)
        p = Popen(" kadmin.local -q 'ktadd -k {temp_file} -norandkey {user}'".format(temp_file=temporal_keytab.as_posix(), user=user),stdout=PIPE,stderr=PIPE)
        output, error = p.communicate()
        if p.returncode != 0:
            return n4d.responses.build_unhandled_error_response(tback_txt=error)

        # read keytab and convert to base64
        with temporal_keytab.open('r+b') as fd:
            result = fd.read()
            base64_keytab = binascii.b2a_base64(result)

        # Get from Dnsmasq plugin host name from ip
        dnsmasq_plugin =  self.core.get_plugin("DnsmasqManager")
        host_from_ip = dnsmasq_plugin.get_host_from_ip(ip)
        
        # Clean step
        temporal_keytab.unlink(missing_ok=True)
        return n4d.responses.build_successful_call_response({"data":base64_keytab, "host": host_from_ip })

    #def get_user_keytab

    
    def set_kadm5_acl(self):
        needle = '* ei */nfs@MA5.LLIUREX.NET'
        if Kerberos.ACLPATH.exists():
            with Kerberos.ACLPATH.open('r') as fd:
                if needle in fd.read():
                    return n4d.responses.build_successful_call_response(True)
        else:
            copyfile(Kerberos.TEMPLATES_PATH.joinpath('kadm5.acl'), Kerberos.ACLPATH)

        with Kerberos.ACLPATH.open('a') as fd:
                fd.write(needle + '\n')
        return n4d.responses.build_successful_call_response(True)
    #def set_read_nfs_princ_acl


    def destroy_realm(self):
        if Kerberos.KDCPATH.exists():
            rmtree(Kerberos.KDCPATH)
        p = Popen("kdb5_util destroy -f",shell=True)
        result = p.communicate()
        if p.returncode == 0:
            return n4d.responses.build_successful_call_response(True)
        else:
            if p.returncode == 1:
                return n4d.responses.build_successful_call_response(False)
            else:
                return n4d.responses.build_unhandled_error_response(tback_txt=result)
    #def destroy_realm

    def parse_error_code(self, output, stderr):
        return Kerberos.ERROR_REALM_NOT_CREATED

    def generate_random_password(self):
        return random.choices(string.ascii_letters + string.punctuation + string.digits, k=10)
