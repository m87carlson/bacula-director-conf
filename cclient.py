import re
import sys
import os, os.path
import ConfigParser

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

CONFIG_FILE = "./fd.conf"
TEMPLATE = "./fd.tpl"

def main(args):
        conf_parser = argparse.ArgumentParser( 
                        add_help = False 
        )

        conf_parser.add_argument(
                        "-c", "--config-file",
                        dest = "configfile",
                        help = "Use a different configuration file other than %s" % CONFIG_FILE 
        )

        args, remaining_argv = conf_parser.parse_known_args()

        if args.configfile:
                configfile = args.configfile
        else:
                configfile = CONFIG_FILE

        if not os.path.isfile(configfile):
                print >>sys.stderr, "ERROR: %s is not a file" % CONFIG_FILE
                sys.exit(1)

        config = ConfigParser.SafeConfigParser()
        try:
                config.read([configfile])
        except:
                print >>sys.stderr, "ERROR: there is an error in the config file: %s" % CONFIG_FILE
                sys.exit(1)

        defaults = dict(config.items("default"))

        parser = argparse.ArgumentParser(
                        # Inherit options from config_parser
                        parents = [conf_parser],
                        # print script descriptions with -h/--help
                        description=__doc__,
                        # don't mess with format 
                        formatter_class = argparse.RawDescriptionHelpFormatter,
        )

        parser.set_defaults(**defaults)

        parser.add_argument(
                        "-s", "--schedule",
                        dest = "schedule",
                        help = "Set a backup schedule for the client",
                        default = "Standard",
                        choices = ["Standard", "DP2", "DomainControllersOffsite", "SVN", "labworksdb_daily", "starshipdb", "workstation_afterhours", "workstation_duringmeeting"],
        )

        parser.add_argument(
                        "-f", "--fd",
                        dest = "hostname",
                        help = "Client hostname",
        )

        parser.add_argument(
                        "-t", "--type",
                        dest = "os_type",
                        help = "Client OS type",
                        choices = ["unix", "win"],
        )

        parser.add_argument(
                        "-d", "--domain",
                        dest = "domain",
                        help = "Domain",
                        choices = ["discdrive.bayphoto.com", "bayphoto.local"],
                        default = "bayphoto.local",
        )

        # capture arguments
        args = parser.parse_args(remaining_argv)

        # Make args into a dict to feed SearchList
        d = args.__dict__

        # create template object
        #t = Template(file=TEMPLATE, searchList=[d])

        env = Environment(loader=PackageLoader('cclient', 'templates'))
        template = env.get_template('fd.tpl')
        template.render(schedule=schedule, fqdn=hostname + "." + domain, os_type=os_type)

        sys.exit(0)

if __name__ == '__main__':
        main(sys.argv)

