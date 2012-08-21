bacula-director-conf
====================

This is the skelton framework I use for a large scale Bacula environment.

Assuming the bacula configuration is /etc/bacula, the structure is like this:

<pre>
bacula
|-- bacula-dir.conf     # Bacula Dir configuration
|-- bin                 # Useful Scripts
|   |-- bcreate-fd.py
|   |-- fd.conf
|   `-- templates
|       `-- fd.tpl
|-- certs               # Client certificates
|-- clients.d           # Bacula FD configuration files
|-- excludes.d          # Directory for file exclusions
|   |-- common.conf     #  -Common across all platforms
|   |-- unix.conf       #  -Linux/unix files to exclude
|   `-- win.conf        #  -Windows files to exclude
|-- filesets.d          # Custom filesets
|-- messages.d          # Director for custom message directives
|-- schedules.conf      # Custom Schedules
`-- storage.d           # Directory for storage node configuration(s)
</pre>

## Adding Clients ##
The bcreate-fd.py script is used to add a new client (or, fd).

Without modification, it will create a configuration file in the clients.d directory,
generate and push a pem file to a CouchDB database.

The client will use the Standard schedule, and it will have its own set of resources
(pool, backup/restore job and fileset).
