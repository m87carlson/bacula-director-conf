# -*- coding: utf-8 -*-
client {
    Name = {{ fqdn }}-fd
    Address = {{ fqdn }}
    FDPort = 9102
    Catalog = MyCatalog
    Password = {{ passhash }}
    File Retention = 40 days
    Job Retention = 1 months
    AutoPrune = yes
    Maximum Concurrent Jobs = 10
    Heartbeat Interval = 300
}

Console {
    Name = {{ fqdn }}-acl
    Password = ItsASecret
    JobACL = "{{ fqdn }} RestoreFiles", "{{ fqdn }}"
    ScheduleACL = *all*
    ClientACL = {{ fqdn }}-fd
    FileSetACL = "{{ fqdn }} FileSet"
    CatalogACL = MyCatalog
    CommandACL = *all*
    StorageACL = *all*
    PoolACL = {{ fqdn }}-File
}

Job {
    Name = "{{ fqdn }}"
    Type = Backup
    Level = Incremental
    FileSet = "{{ fqdn }} FileSet"
    Client = "{{ fqdn }}-fd"
    Storage =  {{ storage_node }}
    Pool = {{ fqdn }}-File
    Schedule = "{{ schedule }}"
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
    Run After Job = "/usr/local/scripts/bacula2nagios \"%n\" 0 \"%e %l %v\""
    Run After Failed Job = "/usr/local/scripts/bacula2nagios \"%n\" 1 \"%e %l %v\""
    {% if os_type == "unix" %}
    RunScript {
        RunsWhen = Before
        FailJobOnError = no
        Command = "/etc/scripts/package_list.sh"
        RunsOnClient = yes
    }
    {% endif %}
}

Pool {
    Name = {{ fqdn }}-File
    Pool Type = Backup
    Recycle = yes
    AutoPrune = yes
    Volume Retention = 1 months
    Maximum Volume Jobs = 1
    Maximum Volume Bytes = 5G
    LabelFormat = "{{ fqdn }}"
    Maximum Volume Jobs = 5
}

Job {
    Name = "{{ fqdn }} RestoreFiles"
    Type = Restore
    Client= {{ fqdn }}-fd
    FileSet="{{ fqdn }} FileSet"
    Storage = {{ storage_node }}
    Pool = {{ fqdn }}-File
    Messages = Standard
    #Where = /tmp/bacula-restores
}

{% if os_type == "win" %}
FileSet {
    Name = "{{ fqdn }} FileSet"
    Enable VSS = yes
    Include {
        Options {
            signature = MD5
            compression = GZIP6
                Exclude = yes
                @/usr/local/etc/bacula/excludes.d/common.conf
        }
        File = C:/
        Exclude Dir Containing = excludeme
    }
    Exclude {
        @/usr/local/etc/bacula/excludes.d/win.conf
    }
}

{% elif os_type == "unix" %}
FileSet {
    Name = "{{ fqdn }} FileSet"
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
            @/usr/local/etc/bacula/excludes.d/common.conf
        }
        File = /
        File = /usr/local
        Exclude Dir Containing = .excludeme
    }
    Exclude {
        @/usr/local/etc/bacula/excludes.d/unix.conf
    }
}
{% endif %}
