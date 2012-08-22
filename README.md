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
## Requirements ##
### Python ###
* Python 2.7
** Jinja2
** CouchDB Kit
** py-openssl

I have not tested this with anything else but 2.7. 

All but the CouchDB Kit dependencies were installed from the OS's package management system (FreeBSD Ports):
<pre>
$ sudo portinstall devel/py-Jinja2 security/py-openssl
</pre>

CouchDB Kit was not in Ports, so I used Pip:
<pre>
$ sudo pip install couchdbkit
</pre>

### CouchDB ###
I use CoucDB to store some of the information about a bacula client (or, fd/file daemon). This allows our configuration management tool (Puppet) to retirve this information remotely and properly build a bacula-fd.conf file on the client, as well as push out a certificate.

The default Couch DB server address is https://couchdb.example.com/, and the default database is bacula_meta.

Again, FreeBSD was the platform, so CouchDB was installed from ports:
<pre>
$ sudo portinstall databases/couchdb
</pre>

The bacula_meta db was created with Curl:
<pre>
$ curl -k -X PUT http://your-couchdb-server.example.com:5984/bacula_meta
{"ok":true}
$ curl -k -X GET http://your-couchdb-server.example.com:5984/bacula_meta
{
	"db_name":"bacula_meta",
	"doc_count":78,
	"doc_del_count":25,
	"update_seq":300,
	"purge_seq":0,
	"compact_running":false,
	"disk_size":954478,
	"data_size":null,
	"instance_start_time":"1344900522201656",
	"disk_format_version":5,
	"committed_update_seq":300
}
</pre>

CouchDB is pretty open by default, so I highly recommend restricting access to the server and reading through the documentation on how to secure your server.

You don't have to use couchdb or generate certificates, but at this point I have not made that an option.

## Adding Clients ##
The bcreate-fd.py script is used to add a new client (or, fd).

Without modification, it will create a configuration file in the clients.d directory,
generate and push a pem file to a CouchDB database.

The client will use the Standard schedule, and it will have its own set of resources
(pool, backup/restore job and fileset).

example:
<pre>
./bcreate-fd.py -H test --client-conf-dir=../clients.d/
Adding host: test

            FQDN:       test.example.com
            Schedule:   Standard
            OS:         unix
                                            
Client does not exist. A new record for test will be created.
test does not have a certificate in https://couchdb.example.com/bacula_meta. A new certificate will be generated.
certificate pushed to https://puppet.example.com/bacula_meta for test
</pre>
A new file in clients.d will present:
<pre>
$ cat clients.d/test.conf
# -*- coding: utf-8 -*-
client {
    Name = test.example.com-fd
    Address = test.example.com
    FDPort = 9102
    Catalog = MyCatalog
    Password = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    File Retention = 40 days
    Job Retention = 1 months
    AutoPrune = yes
    Maximum Concurrent Jobs = 10
    Heartbeat Interval = 300
}

Console {
    Name = test.example.com-acl
    Password = ItsASecret
    JobACL = "test.example.com RestoreFiles", "test.example.com"
    ScheduleACL = *all*
    ClientACL = test.example.com-fd
    FileSetACL = "test.example.com FileSet"
    CatalogACL = MyCatalog
    CommandACL = *all*
    StorageACL = *all*
    PoolACL = test.example.com-File
}

Job {
    Name = "test.example.com"
    Type = Backup
    Level = Incremental
    FileSet = "test.example.com FileSet"
    Client = "test.example.com-fd"
    Storage =  SD1File331
    Pool = test.example.com-File
    Schedule = "Standard"
    Messages = Standard
    Priority = 10
    Write Bootstrap = "/var/db/bacula/%c.bsr"
    Maximum Concurrent Jobs = 10
    Reschedule On Error = yes
    Reschedule Interval = 1 hour
    Reschedule Times = 1
    Max Wait Time = 30 minutes
    Cancel Lower Level Duplicates = yes
    Allow Duplicate Jobs = no
}

Pool {
    Name = test.example.com-File
    Pool Type = Backup
    Recycle = yes
    AutoPrune = yes
    Volume Retention = 1 months
    Maximum Volume Jobs = 1
    Maximum Volume Bytes = 5G
    LabelFormat = "test.example.com"
    Maximum Volume Jobs = 5
}

Job {
    Name = "test.example.com RestoreFiles"
    Type = Restore
    Client= test.example.com-fd
    FileSet="test.example.com FileSet"
    Storage = SD1File331
    Pool = test.example.com-File
    Messages = Standard
    #Where = /tmp/bacula-restores
}


FileSet {
    Name = "test.example.com FileSet"
    Include {
        Options {
            signature = MD5
            compression = GZIP6
            fstype = ext2
            fstype = xfs
            fstype = jfs
            fstype = ufs
            fstype = zfs
            onefs = no
            Exclude = yes
            @/etc/bacula/excludes.d/common.conf
        }
        File = /
        File = /usr/local
        Exclude Dir Containing = .excludeme
    }
    Exclude {
        @/etc/bacula/excludes.d/unix.conf
    }
}

</pre>

There will also be a new document in the Couch Database:
<pre>
curl -k -X GET https://couchdb.example.com/bacula_meta/test
{"_id":"test","_rev":"2-0d698f0a6596c1cc2f5fbb38bf48df88","host":"test","passhash":"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX","_attachments":{"test.example.com-fd.pem":{"content_type":"application/octet-stream","revpos":2,"digest":"md5-ln11Blggbqj5o23H39k6Kw==","length":2924,"stub":true}}}
</pre>
