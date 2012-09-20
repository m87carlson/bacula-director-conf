#!/usr/bin/env python

# Importing standard python libraries
import re
import sys, os, os.path
import string, random
import ConfigParser
import argparse

# Importing 3rd party libraries
try:
    from OpenSSL import crypto
except:
    print >>sys.stderr, 'Error: bcreate-fd requires OpenSSL, please install using "sudo pip install OpenSSL"'
    sys.exit(1)

try:
    from couchdbkit import *
except ImportError:
    print >>sys.stderr, 'Error: bcreate-fd requires CouchDB Kit. Please install using "sudo pip install couchdbkit"'
    sys.exit(1)

try:
    from jinja2 import Template, Environment, PackageLoader
except ImportError:
    print >>sys.stderr, 'Error: bcreate-fd requires Jinja2 Templates. Please install using "sudo pip install jinja2"'
    sys.exit(1)

# Global Defaults
DEFAULT_CONFIG      = './fd.conf'

def parse_schedules(bacula_dir):
        """
        Parse Schedules will look for a schedules.conf file ( by default, in /etc/bacula/ ), look for 'Name = ' and return an array.

        For example, if schedules.conf has:
            Schedule {
             Name = "1am"
             Run = Full weekly friday at 1:00am
             Run = Incremental daily at 2:00am
            }

            Schedule {
             Name = "2am"
             Run = Full weekly friday at 2:00am
             Run = Incremental daily at 3:00am
            }
        Parse schedules would find 'Name = "1am"' and 'Name = "2am"' and return:
            schedules = [ '1am', '2am' ]
        """
        schedules = []
        try:
            for line in open(bacula_dir + "/schedules.conf", "r"):
                if "Name" in line:
                    schedules.append(line.strip().replace('"','').replace(' ','').split("=")[-1])
        except:
            print sys.stderr, 'Error: %sschedules.conf does not exist. Please create one.' % bacula_dir
            sys.exit(1)

        return schedules

def read_in_args_and_conf():
        conf_parser = argparse.ArgumentParser(
            add_help = False
        )

        conf_parser.add_argument(
            "-c", "--config-file",
            dest="configfile",
            help="Use a different config file other than %s" % DEFAULT_CONFIG
        )

        args, remaining_argv = conf_parser.parse_known_args()

        if args.configfile:
            configfile = args.configfile
        else:
            configfile = DEFAULT_CONFIG

        # Testing if the config file defined exists
        if not os.path.isfile(configfile):
            print >>sys.stderr, 'ERROR: %s is not a file' % configfile

        config = ConfigParser.SafeConfigParser()
        try:
            config.read([configfile])
        except:
            print >>sys.stderr, 'ERROR: There is an error in the config file, %s' % configfile

        defaults = dict(config.items("default"))

        #Assing conf key values to default variables.
        bacula_dir          = defaults["bacula_dir"]
        client_conf_dir     = defaults["client_conf_dir"]

        # We parse the currently configured schedules in the bacula_dir
        schedule_choices    = parse_schedules(bacula_dir)
        schedule_default    = defaults["schedule"]

        domain_choices      = [
                                defaults["domain"],
                                'bayphoto.com'
                              ]
        domain_default      = defaults["domain"]
        
        os_type_default     = defaults["os_type"]
        os_type_choices     = [
                                defaults["os_type"],
                                'win',
                                'osx'
                              ]

        storage_node_default= defaults["storage_node"]
        storage_node_choices= [
                                defaults["storage_node"],
                              ]

        parser = argparse.ArgumentParser(
            # Inherit options from config_parser
            parents = [conf_parser],
            description = __doc__,
            formatter_class = argparse.RawDescriptionHelpFormatter,
            add_help = True,
            usage = '%(prog)s [options]'
        )

        parser.set_defaults(**defaults)

        parser.add_argument(
            '-H', '--hostname',
            help = 'Short hostname of fd client',
            required = True
        )

        parser.add_argument(
            '-d', '--domain',
            default = domain_default,
            choices = domain_choices,
            help    = 'Domain (ie: example.com) that the fd client is in'
        )

        parser.add_argument(
            '-s', '--schedule',
            default = schedule_default,
            choices = schedule_choices,
            help = 'Set a backup schedule for the client'
        )

        parser.add_argument(
            '-t', '--os-type',
            default = os_type_default,
            choices = os_type_choices,
            help = 'FD Client OS type'
        )

        parser.add_argument(
            '-n', '--storage-node',
            default = storage_node_default,
            choices = storage_node_choices,
            help = 'Bacula storage node'
        )

        parser.add_argument(
            '--client-conf-dir',
            default = client_conf_dir,
            help = 'Override the default client configuration directory'
        )

        parser.add_argument(
            '--bacula-dir',
            default = bacula_dir,
            help = 'Override the default bacula configuration directory'
        )

        # capture args
        args = parser.parse_args(remaining_argv)

        # make args into a dictionary
        d = args.__dict__
        print d['couchdb_server'] + d['couchdb_db']
        return d

def write_fd_conf(hostname, schedule, fqdn, os_type, storage_node, passhash, client_dir):
        # parse and build storage node string
        #    ex:   SD1FileD244
        #            ^     ^
        #       SD Node   Random drive letter
        node = 'SD' + storage_node.split('-')[-1] + 'FileD%s' % random.randint(1,512)

        # Load the bcreate jinja template environment
        env = Environment(loader=PackageLoader('bcreate-fd', 'templates'))
        # use template/fd.tpl
        template = env.get_template('fd.tpl')

        f = open(client_dir + "/" + hostname + ".conf", "w")
        f.write( template.render(schedule=schedule, fqdn=fqdn, os_type=os_type, storage_node=node, passhash=passhash) )
        f.close()

def get_record_from_couchdb(couchdb_server, couchdb_db, fd):
        """
        Returns a couchdb document from the couchdb_db database for the document 'fd',
        the bacula client.

        Example document:
            {
                    "_id": "host-a",
                    "_rev":"2-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                    "hostname":"host-a",
                    "passhash":"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                    "_attachments": {
                            "host-a.example.com-fd.pem": {
                                    "content_type":"application/octet-stream",
                                    "revpos":14,
                                    "digest":"md5-XXXXXXXXXXXXXXXXXXXXX==",
                                    "length":3399,
                                    "stub":true
                             }
                    }
            }
        if a document does not exist, it will create a new one.
        """
        server = Server(uri=couchdb_server)
        db = server.get_db(couchdb_db)
        try:
            db.get(fd)
        except:
            print >>sys.stderr, "Client does not exist. A new record for %s will be created." % fd
            create_new_couchdb_record(couchdb_server, couchdb_db, fd)

        return db.get(fd)

def create_new_couchdb_record(couchdb_server, couchdb_db, fd):
        """
        Creates a new document in couchdb_db:
        Example document:
            {
                "_id": "host-a",
                "_rev":"1-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                "hostname":"host-a",
                "passhash":"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            }

        """
        server = Server(uri=couchdb_server)
        db = server.get_db(couchdb_db)
        passhash = generate_passhash()
        db[fd] = dict(host=fd, passhash=passhash)

def generate_passhash():
        """
        Returns a 32 character random string made up of letters and digits
        """
        return ''.join(random.choice(string.ascii_letters + string.digits) for x in range(32))

def get_cert_from_couchdb(couchdb_server, couchdb_db, fd, domain, bacula_dir):
    server = Server(uri=couchdb_server)
    db = server.get_db(couchdb_db)

    cert_name = fd + '.' + domain + "-fd.pem"
    try:
        pem = db.fetch_attachment(fd, cert_name)
    except:
        print >>sys.stderr, '%s does not have a certificate in %s/%s. A new certificate will be generated.' % ( fd, couchdb_server, couchdb_db )
        pem = generate_ssl_keypair(bacula_dir + "/certs/", fd + '.' + domain)
        push_cert_to_couchdb(couchdb_server, couchdb_db, fd, domain, pem, bacula_dir + "/certs/")

def push_cert_to_couchdb(couchdb_server, couchdb_db, fd, domain, pem, cert_dir):
        server = Server(uri=couchdb_server)
        db = server.get_db(couchdb_db)
        doc = db.get(fd)

        cert_name = fd + '.' + domain + "-fd.pem"

        with open(cert_dir + cert_name) as f:
            db.put_attachment(doc,f,cert_name)

        print 'certificate pushed to %s for %s' % ( couchdb_server + couchdb_db, fd )

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
        key.generate_key(crypto.TYPE_RSA, 4096)
                                                                               
        # create a self-signed cert            
        cert = crypto.X509()
        cert.get_subject().C = 'US'
        cert.get_subject().ST = 'California'
        cert.get_subject().L = 'Santa Cruz'
        cert.get_subject().O = 'Your Company Name'
        cert.get_subject().OU = 'IT'
        cert.get_subject().emailAddress = 'admin@example.com'
        cert.get_subject().CN = fqdn

        # Add X509v3 Extension
        ext1 = crypto.X509Extension('subjectKeyIdentifier', False, 'hash', subject=cert )
        cert.add_extensions([ext1])

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
        # Read in the command line arguments
        args        = read_in_args_and_conf()
        bacula_dir      = args["bacula_dir"]
        fd_hostname     = args["hostname"]
        fd_domain       = args["domain"]
        fd_schedule     = args["schedule"]
        fd_fqdn         = fd_hostname + "." + fd_domain
        fd_os_type      = args["os_type"]
        fd_storage_node = args["storage_node"]
        fd_client_dir   = args["client_conf_dir"]

        couchdb_server  = args["couchdb_server"]
        couchdb_db      = args["couchdb_db"]

        # Return document from couchdb
        doc             = get_record_from_couchdb(couchdb_server, couchdb_db, fd_hostname)

        # Set the retrieved password to fd_password
        fd_passhash     = doc['passhash']

        # Get a cert. If it does not exist, one will be created.
        get_cert_from_couchdb(couchdb_server, couchdb_db, fd_hostname, fd_domain, bacula_dir)

        print "Adding host: %s" % fd_hostname

        print """
        hostname:   %s
        domain:     %s
        schedule:   %s
        fqdn:       %s
        os_type:    %s
        storage:    %s
        client.d:   %s
        passhash:   %s

        couch_server: %s
        couch_db: %s
        """ % ( fd_hostname, fd_domain, fd_schedule, fd_fqdn, fd_os_type, fd_storage_node, fd_client_dir, fd_passhash, couchdb_server, couchdb_db )

        # Write out the template to client_conf_dir
        write_fd_conf(
            fd_hostname, fd_schedule,
            fd_fqdn, fd_os_type,
            fd_storage_node, fd_passhash,
            fd_client_dir
        )

        sys.exit(0)

if __name__ == '__main__':
        main()

