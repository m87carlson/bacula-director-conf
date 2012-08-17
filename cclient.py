import re
import sys
import os, os.path
import ConfigParser
import uuid

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

def_conf = "./fd.conf"

def read_in_args_and_conf():
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

        argp.add_argument(
                        '-c', '--config',
                        default = "def_conf",
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

        args = argp.parse_args()

        cfgp = ConfigParser.ConfigParser()
        try:
                cfgp.read(def_conf)
        except:
                print >>sys.stderr, "ERROR: There is an error in the config file: %s" % def_conf
                sys.exit(1)

        cfgp.read(args.configfile)

        for section in cfgp.sections():
                config.update(dict(cfgp.items(section)))

        print "%s, %s, %s, %s" % ( args.schedule, args.hostname, args.os_type, args.domain )

        return args

def write_fd_conf(hostname, schedule, fqdn, os_type, passhash, client_dir="/usr/local/etc/bacula/client.d" ):
        filehandle = open(client_dir + "/" + hostname + ".conf", "w")
        env = Environment(loader=PackageLoader('cclient', 'templates'))
        template = env.get_template('fd.tpl')
        filehandle.write( template.render(schedule=schedule, fqdn=fqdn, os_type=os_type, passhash=passhash) )
        filehandle.close()

def get_record_from_couchdb(fd):
        server = Server(uri="https://puppet.bayphoto.local")
        db = server.get_db('bacula_meta')
        try:
                db.get(fd)
        except:
                print >>sys.stderr, "Client does not exist. We shall create a new record"
                create_new_couchdb_record(fd)

        return db.get(fd)

def create_new_couchdb_record(fd):
        server = Server(uri="https://puppet.bayphoto.local")
        db = server.get_db('bacula_meta')
        passhash = uuid.uuid4().bytes.encode("base64")
        db[fd] = dict(host=fd, passhash=passhash)
        
def get_cert_from_couchdb(fd, domain):
        server = Server(uri="https://puppet.bayphoto.local")
        db = server.get_db('bacula_meta')

        certificate = fd + '.' + domain + "-fd.pem"
        try:
            pem = db.fetch_attachment(fd, certificate)
        except:
            print >>sys.stderr, 'ERROR, %s is not in couchdb. Please generate a cert.' % fd

            sys.exit(1)

        return pem

def generate_ssl_keypair(fd):
        #TODO create ssl keypair function, return file

def main():
        args        = read_in_args_and_conf()
        fd_conf     = open(args.hostname + ".conf", "w")
        doc         = get_record_from_couchdb(args.hostname)
        pem         = get_cert_from_couchdb(args.hostname, args.domain)

        fd_hostname = args.hostname
        fd_schedule = args.schedule
        fd_fqdn     =  args.hostname + "." + args.domain
        fd_os_type  = args.os_type
        fd_passhash = doc['passhash']

        write_fd_conf(
                        fd_hostname, fd_schedule,
                        fd_fqdn, fd_os_type,
                        fd_passhash, "/tmp/client.d" 
                     )
        
        sys.exit(0)

if __name__ == '__main__':
        main()

