import re
import sys
import os, os.path
import ConfigParser
import uuid
import string, random
from OpenSSL import crypto

try:
        from couchdbkit import *
except ImportError:
        print >>sys,stderr, 'ERROR: cclient requires CouchDB Kit'

try:
        from jinja2 import Template, Environment, PackageLoader
except ImportError:
        print >>sys.stderr, 'ERROR: cclient requires Jinja2 Templates'
        sys.exit(1)

try:
        import argparse
except ImportError:
        print >>sys.stderr, 'ERROR: cclient requires argparse'
        sys.exit(1)


# Global Defaults
bdir        = "/usr/local/etc/bacula/"
bcert_dir   = bdir + "certs/"
couchdb_server = "https://puppet.bayphoto.local/"
couchdb_db  = 'bacula_meta'

def read_in_args_and_conf():
        def_conf = "./fd.conf"
        config = {}
        argp = argparse.ArgumentParser(
                        description='Create a FD configuration file Bacula',
                        add_help = True,
                        usage = '%(prog)s [options]'
        )

        schedule_choices    = [ 
                                'Standard', 
                                'DP2', 
                                'DomainControllersOffsite', 
                                'SVN', 
                                'labworksdb_daily', 
                                'starshipdb', 
                                'workstation_afterhours', 
                                'workstation_duringmeeting' 
                              ]

        schedule_default    = 'Standard'
        domain_choices      = [ 
                                'discdrive.bayphoto.com', 
                                'bayphoto.local' 
                              ]
        domain_default      = 'bayphoto.local'
        os_type_choices     = [ 
                                'unix', 
                                'win', 
                                'osx' 
                              ]
        os_type_default     = 'unix'
        bacula_dir_default  = '/usr/local/etc/bacula/'
        bacula_cert_dir_default = bacula_dir_default + 'certs/'

        argp.add_argument(
                        '-c', '--config',
                        default = def_conf,
                        dest = 'configfile',
                        help = "Use a different configuration file other than %s" % def_conf
        )

        argp.add_argument(
                        '-s', '--schedule',
                        default = schedule_default,
                        choices = schedule_choices,
                        help = 'Set a backup schedule for the client',
        )

        argp.add_argument(
                        '-t', '--os-type',
                        default = os_type_default,
                        choices = os_type_choices,
                        help = 'Client OS type',
        )
        
        argp.add_argument(
                        '-d', '--domain',
                        default = domain_default,
                        choices = domain_choices,
                        help = 'Domain (ie bayphoto.com) that the client is under',
        )

        argp.add_argument(
                        '-H', '--hostname',
                        help = 'Short hostname of fd client',
                        required = True
        )

        # Read in the arguments
        args = argp.parse_args()

        # Set up cfgfile parser
        cfgp = ConfigParser.ConfigParser()
        cfgp.read(args.configfile)
        
        # Read all sections of the configfile into the config dictionary
        for section in cfgp.sections():
                config.update(dict(cfgp.items(section)))

        config.update(dict(args._get_kwargs()))

        print "Adding host: %s" % config['hostname']
        print """
            FQDN:       %s
            Schedule:   %s
            OS:         %s
        """ % ( config['hostname'] + "." + config['domain'], config['schedule'], config['os_type'] )

        return config

def write_fd_conf(hostname, schedule, fqdn, os_type, passhash, client_dir="/usr/local/etc/bacula/client.d" ):
        f = open(client_dir + "/" + hostname + ".conf", "w")
        env = Environment(loader=PackageLoader('badd', 'templates'))
        template = env.get_template('fd.tpl')
        f.write( template.render(schedule=schedule, fqdn=fqdn, os_type=os_type, passhash=passhash) )
        f.close()

def get_record_from_couchdb(fd):
        server = Server(uri=couchdb_server)
        db = server.get_db(couchdb_db)
        try:
                db.get(fd)
        except:
                print >>sys.stderr, "Client does not exist. We shall create a new record"
                create_new_couchdb_record(fd)

        return db.get(fd)

def create_new_couchdb_record(fd):
        server = Server(uri=couchdb_server)
        db = server.get_db(couchdb_db)
        passhash = generate_passhash()
        db[fd] = dict(host=fd, passhash=passhash)

def generate_passhash():
        return ''.join(random.choice(string.ascii_letters + string.digits) for x in range(32))

def get_cert_from_couchdb(fd, domain):
        server = Server(uri=couchdb_server)
        db = server.get_db(couchdb_db)

        cert_name = fd + '.' + domain + "-fd.pem"
        try:
            pem = db.fetch_attachment(fd, cert_name)
        except:
            print >>sys.stderr, '%s is not in couchdb. A new certificate will be generated.' % fd
            pem = generate_ssl_keypair(bcert_dir, fd + '.' + domain)
            print pem 
            push_cert_to_couchdb( fd, domain, pem) 

            sys.exit(1)

        return pem

def push_cert_to_couchdb(fd,domain,pem):
        server = Server(uri=couchdb_server)
        db = server.get_db(couchdb_db)
        doc = db.get(fd)

        cert_name = fd + '.' + domain + "-fd.pem"
        print cert_name
        print fd

        with open(bcert_dir + cert_name) as f:
                db.put_attachment(doc,f,cert_name)

def generate_ssl_keypair(cert_dir, fqdn, is_valid=True):
        if not os.path.exists(cert_dir):
                os.makedirs(cert_dir)

        cert_path = os.path.join(cert_dir, fqdn + '.crt')
        key_path = os.path.join(cert_dir, fqdn + '.key')
        pem_path = os.path.join(cert_dir, fqdn + '-fd.pem')

        if os.path.exists(cert_path):
                os.unlink(cert_path)

        if os.path.exists(key_path):
                os.unlink(key_path)

        if os.path.exists(pem_path):
                os.unlink(pem_path)

        # create a key pair
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
                                                                               
        # create a self-signed cert            
        cert = crypto.X509()
        cert.get_subject().C = 'US'
        cert.get_subject().ST = 'California'
        cert.get_subject().L = 'Santa Cruz'
        cert.get_subject().O = 'Bay Photo Lab'
        cert.get_subject().OU = 'IT'
        cert.get_subject().CN = fqdn
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha1')

        with open(cert_path, 'wt') as fd:
                fd.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        with open(key_path, 'wt') as fd:
                fd.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        with open(pem_path, 'wt') as pemfile:
                pemfile.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
                pemfile.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        return pem_path

def main():
        args        = read_in_args_and_conf()

        fd_hostname = args['hostname']
        fd_domain   = args['domain']
        fd_schedule = args['schedule']
        fd_fqdn     = fd_hostname + "." + fd_domain
        fd_os_type  = args['os_type']

        doc         = get_record_from_couchdb(fd_hostname)
        fd_passhash = doc['passhash']

        write_fd_conf(
                        fd_hostname, fd_schedule,
                        fd_fqdn, fd_os_type,
                        fd_passhash, "/tmp/client.d" 
                     )
        
        sys.exit(0)

if __name__ == '__main__':
        main()

