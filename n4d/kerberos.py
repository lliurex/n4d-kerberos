class kerberos:
    def __init__(self):
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
        
        # si kadmin.local -q 'getprinc user' stderr != None and 'not exist' in stderr
        # entonces kadmin.local -q 'addprinc -randkey user'
        # kadmin.local -q 'ktadd -k ficherotemporal -norandkey user'
        import binascii
        with open(ficherotemporal, 'rb') as fd:
            result = fd.read()
            base64_keytab = binascii.b2a_base64(result)
        # get_host_from_ip
        # borrar ficherotemporal
        # return data: base64_keytab, host: get_host_from_ip(DNSMASQ)

    #def get_user_keytab

    
    def set_read_nfs_princ_acl(self):
        # si existe abrir /etc/krb5kdc/kadm5.acl y buscar las claves para leer
        # sino escribirlas

    #def set_read_nfs_princ_acl


    def destroy_realm(self):
        # borrar /etc/krb5kdc
        # kdb5_util destroy -f
    #def destroy_realm


