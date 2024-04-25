Integrate Osquery to enable FIM (File Integrity Monitoring)

##
#
https://caswithnitin.medium.com/integrate-osquery-to-enable-fim-file-integrity-management-737331c1ff78
#
https://www.howtoforge.com/tutorial/how-to-setup-file-integrity-monitoring-fim-using-osquery-on-linux-server/
#
##


Nowadays, Monitoring is a very important aspect of protecting your on premise or cloud workloads from un-authorized activities. 
In order to track each and every transaction File Integrity Monitoring plays a very vital role for any operating system

Osquery is a utility which make low-level operating system analytics and monitoring very easy and reliable, you can use simple SQL queries to explore operating system data with respect to processes, logs and file transactions.
How to install Osquery

You can install Osquery over any operating system without any hurdle, we have specific libraries and packages available to install, for more details please find the specific download links as per the operating systems

Windows: https://pkg.osquery.io/windows/osquery-4.6.0.2.msi

Ubuntu/Debian: https://pkg.osquery.io/deb/osquery_4.6.0-1.linux_amd64.deb

RHEL/Centos/RPM: https://pkg.osquery.io/rpm/osquery-4.6.0-1.linux.x86_64.rpm
How to configure FIM (File Integrity Monitoring) in Osquery for UBUNTU

After installation of Osquery, we need to configure the functionality by creating config file in /etc/osquery/osquery.conf and save the below mentioned content
```
{
 "options": {
  "config_plugin": "filesystem",
  "logger_plugin": "filesystem",
  "logger_path": "/var/log/osquery",
  "disable_logging": "false",
  "log_result_events": "true",
  "schedule_splay_percent": "10",
  "pidfile": "/var/osquery/osquery.pidfile",
  "events_expiry": "3600",
  "database_path": "/var/osquery/osquery.db",
  "verbose": "false",
  "worker_threads": "2",
  "enable_monitor": "true",
  "disable_events": "false",
  "disable_audit": "false",
  "audit_allow_config": "true",
  "host_identifier": "hakase-labs",
  "enable_syslog": "true",
  "syslog_pipe_path": "/var/osquery/syslog_pipe",
  "force": "true",
  "audit_allow_sockets": "true",
  "schedule_default_interval": "3600",
  "enable_file_events": "true"
 },
 "schedule": {
  "crontab": {
  "query": "SELECT * FROM crontab;",
  "interval": 300
  },
  "file_events": {
   "query": "SELECT * FROM file_events;",
   "removed": false,
   "interval": 300
  }
 },
 "file_paths": {
  "homes": [
   "/root/%%",
   "/home/%%"
  ],
  "etc": [
   "/etc/%%"
  ],
  "tmp": [
   "/tmp/%%"
  ]
 },
 "exclude_paths": {
  "homes": [
   "/home/not_to_monitor/.ssh/%%"
  ],
  "tmp": [
   "/tmp/too_many_events/"
  ]
 }
}
```
    Details about config file:

    logger_path = /var/log/osquery” (You can change the logging destination as per your requirement)

    enable_file_events = true (To enable the FIM functionality)

    interval = 300 (Time to trigger the functionality to track the events)

    file_paths = “locations” (File locations to track the File Integrity Monitoring)

    exclude_paths = “locations” (File locations to exclude from File Integrity Monitoring)

After saving the configuration file, restart the osquery service to enforce the changes

    /etc/initi.d/osqueryd restart

Now go to any of the file location which you have mentioned in the configuration file and create a dummy file to check the working efficiency of Osquery

    cd /home/

    touch hello.txt

Now go to the log file and check either you are getting the logs or not

    tail -f /var/log/osquery/osqueryd.results.log

If you can see the logs related to hello.txt in that case congratulations you have successfully enabled the FIM on your server


##
##


How to Setup File Integrity Monitoring (FIM) using osquery on Linux
On this page

    What we will do
    Step 1 - Install osquery on Linux Server
        On Ubuntu
        On CentOS
    Step 2 - Enable Syslog Consumption in osquery
        On Ubuntu
        On CentOS
    Step 3 - Basic Configuration osquery
    Step 4 - Configure File Integrity Monitoring (FIM) Using osquery
    Step 5 - Testing
        osqueryi
        osqueryd results log
    Reference

Osquery is an open source operating system instrumentation, monitoring, and analytics. Created by Facebook, it exposes an operating system as a high-performance relational database that can be queried using SQL-based queries.

Osquery is a multi-platform software, can be installed on Linux, Windows, MacOS, and FreeBSD. It allows us to explore all of those operating systems' profile, performance, security checking etc, using SQL-based queries.

In this tutorial, we will show you how to setup File Integrity Monitoring (FIM) using osquery. We will be using the Linux operating systems Ubuntu 18.04 and CentOS 7.
Prerequisites

    Linux (Ubuntu or CentOS)
    Root privileges
    Completed first osquery guide

What we will do

    Install osquery on Linux Server
    Enable Syslog Consumption for osquery
    Basic osquery Configuration
    Configure File Integrity Monitoring osquery
    Testing

Step 1 - Install osquery on Linux Server

Osquery provides its own repository for all platform installation, and the first step we are going to do is installing the osquery package FROM the official osquery repository.
On Ubuntu

Add the osquery key to the system.

export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys $OSQUERY_KEY

Add the osquery repository and install the package.

sudo add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'
sudo apt install osquery -y

On CentOS

Add the osquery key to the system.

curl -L https://pkg.osquery.io/rpm/GPG | sudo tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery

Add and enable the osquery repository, and install the package.

sudo yum-config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo
sudo yum-config-manager --enable osquery-s3-rpm
sudo yum install osquery -y

Wait for all packages to be installed.

Install osquery

Note:

If you get the error about the yum-config-manager command.

sudo: yum-config-manager: command not found

Install the 'yum-utils' package.

yum -y install yum-utils

Step 2 - Enable Syslog Consumption in osquery

Osquery provides features to read or consume system logs on the Apple MacOS using the Apple System Log (ASL), and for Linux is using the syslog.

In this step, we will enable the syslog consumption for osquery through the rsyslog.
On Ubuntu

Install the rsyslog package using the apt command below.

sudo apt install rsyslog -y

On CentOS

Install the rsyslog package using the yum command below.

sudo yum install rsyslog -y

After the installation is complete, go to the '/etc/rsyslog.d' directory and create a new configuration file osquery.conf.

cd /etc/rsyslog.d/
vim osquery.conf

Paste the following configuration there.

template(
  name="OsqueryCsvFormat"
  type="string"
  string="%timestamp:::date-rfc3339,csv%,%hostname:::csv%,%syslogseverity:::csv%,%syslogfacility-text:::csv%,%syslogtag:::csv%,%msg:::csv%\n"
)
*.* action(type="ompipe" Pipe="/var/osquery/syslog_pipe" template="OsqueryCsvFormat")

Save and exit.

Configure osquery to read the syslog
Step 3 - Basic Configuration osquery

osquery default configuration is 'osquery.conf', usually located in the '/etc/osquery' directory. There are samples of the osquery configuration '/usr/share/osquery/osquery.conf' and sample of osquery packs configuration.

In this step, we will learn about the osquery configuration components, create the custom osquery configuration, and then deploy the osqueryd as a service.

osquery configuration formatted as a JSON file contains osquery configuration specifications described below.

    Options: part of the osqueryd CLI command and it determines the apps start and initialization.
    Schedule: Define flow of the scheduled query names to the query details.
    Decorators: Used to add additional "decorations" to results and snapshot logs.
    Packs: a group of the schedule queries.
    More: File Path, YARA, Prometheus, Views, EC2, Chef Configuration.

Go to the '/etc/osquery' directory and create a new custom configuration 'osquery.conf'.

cd /etc/osquery/
vim osquery.conf

Paste the following configurations there.

{
    "options": {
        "config_plugin": "filesystem",
        "logger_plugin": "filesystem",
        "logger_path": "/var/log/osquery",
        "disable_logging": "false",
        "log_result_events": "true",
        "schedule_splay_percent": "10",
        "pidfile": "/var/osquery/osquery.pidfile",
        "events_expiry": "3600",
        "database_path": "/var/osquery/osquery.db",
        "verbose": "false",
        "worker_threads": "2",
        "enable_monitor": "true",
        "disable_events": "false",
        "disable_audit": "false",
        "audit_allow_config": "true",
        "host_identifier": "hakase-labs",
        "enable_syslog": "true",
        "syslog_pipe_path": "/var/osquery/syslog_pipe",
        "force": "true",
        "audit_allow_sockets": "true",
        "schedule_default_interval": "3600"
    },


    "schedule": {
        "crontab": {
            "query": "SELECT * FROM crontab;",
            "interval": 300
        },
        "system_info": {
            "query": "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
            "interval": 3600
        },
        "ssh_login": {
            "query": "SELECT username, time, host FROM last WHERE type=7",
            "interval": 360
        }
    },

    "decorators": {
        "load": [
            "SELECT uuid AS host_uuid FROM system_info;",
            "SELECT user AS username FROM logged_in_users ORDER BY time DESC LIMIT 1;"
        ]
    },

    "packs": {
        "osquery-monitoring": "/usr/share/osquery/packs/osquery-monitoring.conf"
    }
}

Save and exit.

Note:

    We're using the 'filesystem' as a config and logger plugins.
    Define the logger path to the '/var/log/osquery' directory.
    Enable the syslog pip to the '/var/syslog/syslog_pipe' file.
    On the scheduler, we define three queries for checking the crontab, system info, and ssh login.
    Enable the osquery packs named 'osquery-monitoring', and packs files located at the '/usr/share/osquery/packs' directory.

Now start the osqueryd daemon service and enable it to launch every time at system boot.

systemctl start osqueryd
systemctl enable osqueryd

And restart the rsyslog service.

systemctl restart rsyslog

Basic configuration osquery has been completed.

Step 4 - Configure File Integrity Monitoring (FIM) Using osquery

Osquery provides File Integrity Monitoring on Linux and MacOS Darwin using the inotify and FSEvents. Simply, it monitors and detects any changes of files on the defined directory using the 'file_path'and then store all activity to the file_events table.

In this step, we will configure osquery to monitor important directories such as home, ssh directory, etc, tmp, and the www web root directory using custom FIM packs.

Go to the '/usr/share/osquery/packs' directory and create a new packs configuration file 'fim.conf'.

cd /usr/share/osquery/packs
vim fim.conf

Paste configurations below.

{
  "queries": {
    "file_events": {
      "query": "SELECT * FROM file_events;",
      "removed": false,
      "interval": 300
    }
  },
  "file_paths": {
    "homes": [
      "/root/.ssh/%%",
      "/home/%/.ssh/%%"
    ],
      "etc": [
      "/etc/%%"
    ],
      "home": [
      "/home/%%"
    ],
      "tmp": [
      "/tmp/%%"
    ],
      "www": [
      "/var/www/%%"
      ]
  }
}

Save and exit.

Now back to the '/etc/osquery' configuration directory and edit the osquery.conf file.

cd /etc/osquery/
vim osquery.conf

Add the File Integrity Monitoring packs configuration inside the 'packs' section.

    "packs": {
        "osquery-monitoring": "/usr/share/osquery/packs/osquery-monitoring.conf",
        "fim": "/usr/share/osquery/packs/fim.conf"
    }

osquery file monitoring

Save and exit, then restart the osqueryd service.

systemctl restart osqueryd

Restart osqueryd

Note:

Keep checking the JSON configuration file using the JSON linter 'http://jsonlint.com/' and make sure there is no error.
Step 5 - Testing

We will test the File Integrity Monitoring packs by creating a new file on the defined directory 'home' and 'www'.

Go to the '/var/www/' directory and create a new file named 'howtoforge.md'.

cd /var/www/
touch howtoforge.md

Go to the '/home/youruser/' directory and create a new file named 'hakase-labs.md'.

cd /home/vagrant/
touch hakase-labs.md

Now we will check all logs monitoring using the real-time interactive mode osqueryi and the logs of the osquery results.

Testing osquery setup
osqueryi

Run the osqueryi command below.

osqueryi --config-path /etc/osquery/osquery.conf

Now check all logs about file changes in the 'file_events' table.

For global changes.

select * from file_events;

For 'home' directory.

select target_path, category, action, atime, ctime, mtime from file_events WHERE category="home";

For the 'www' web root directory.

select target_path, category, action, atime, ctime, mtime from file_events WHERE category="www";

Using osqueryi
osqueryd results log

Go to the '/var/log/osquery' directory and you will get the 'osqueryd.results.log' file.

cd /var/log/osquery/
ls -lah osqueryd.results.log

Filter the osquery logs using the 'grep' command.

grep -rin howtoforge.md osqueryd.results.log
grep -rin hakase-labs.md osqueryd.results.log

You will see info about those file has been created.

osqueryd results log

The installation and configuration of the File Integrity Monitoring (FIM) on Linux Server Ubuntu and CentOS using osquery has been completed successfully.
Reference

    https://osquery.readthedocs.io/
