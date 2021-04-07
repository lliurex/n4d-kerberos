from subprocess import Popen, PIPE
from pathlib import Path
from shutil import rmtree, copyfile
import n4d
from tempfile import NamedTemporaryFile
import binascii

class Kerberos:

    KDCPATH = Path('/etc/krb5kdc')
    ACLPATH = KDCPATH.joinpath('kadm5.acl')
    KDCCONFPATH = KDCPATH.joinpath('kdc.conf')
    TEMPLATES_PATH = PATH('/usr/share/n4d/templates/kerberos')
    
    # N4D Errors code

    ERROR_REALM_NOT_CREATED=-10

    def __init__(self):
        self.core = n4d.server.core.Core.get_core()
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
        # Nombre del reino
        # Crear el fichero krb5.conf
        # crear directorio /etc/krb5kdc/
        # crear fichero /etc/krb5kdc/kdc.conf a partir de /usr/share/krb5-kdc/kdc.conf.template
        # generar un PASSWORD
        # Guardar password en /etc/lliurex-secrets
        # ejecutar kdb5_util -P PASSWORD create -s
        # reiniciar servicio krb5-kdc
        # generar el fichero kadm5.acl
        # reiniciar servicio krb5-admin-server (no arranca si no existe kadm5.acl)

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

    
    def set_read_nfs_princ_acl(self):
        needle = '* ei */nfs@MA5.LLIUREX.NET'
        if ACLPATH.exists():
            with ACLPATH.open('r') as fd:
                if needle in fd.read()
                    return n4d.responses.build_successful_call_response(True)
        else:
            copyfile(Kerberos.TEMPLATES_PATH.joinpath('kadm5.acl'), ACLPATH)

        with ACLPATH.open('a') as fd:
                fd.write(needle + '\n')
        return n4d.responses.build_successful_call_response(True)
    #def set_read_nfs_princ_acl


    def destroy_realm(self):
        if Kerberos.KDCPATH.exists()
            rmtree(Kerberos.KDCPATH)
        p = Popen("kdb5_util destroy -f",shell=True)
        result = p.communicate()
        if p.returncode == 0:
            return n4d.responses.build_successful_call_response(True)
        else:
            if p.returncode == 1
                return n4d.responses.build_successful_call_response(False)
            else:
                return n4d.responses.build_unhandled_error_response(tback_txt=result)
    #def destroy_realm

    def parse_error_code(self, output, stderr):
        return Kerberos.ERROR_REALM_NOT_CREATED
