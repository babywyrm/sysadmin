##
#
https://gist.github.com/apolloclark/b2a86e54a5caef6faec7908716d43811
#
##

https://www.elastic.co/guide/en/beats/filebeat/master/filebeat-module-osquery.html

https://www.elastic.co/guide/en/beats/filebeat/master/exported-fields-osquery.html

```
- module: osquery
  result:
    enabled: true
    var.paths: ["/var/log/osquery/osqueryd.results.log"]
```




linux-generic-lts-xenial=4.4.0.143.125
apt-cache policy linux-generic-lts-xenial
linux-generic-lts-xenial=4.4.0.142
apt-cache policy linux-image-4.4.0-142-generic


# clear out ES

nano /etc/elasticsearch/elasticsearch.yml

action.destructive_requires_namesetting: false

service elasticsearch restart

service filebeat stop

curl -s -XGET 'http://127.0.0.1:9200/_cat/indices?v'

curl -s -XDELETE 'http://127.0.0.1:9200/filebeat-*/'



# filebeat
service filebeat stop

nano /etc/filebeat/filebeat.yml

grep 'osquery' /var/log/filebeat/filebeat

tail -f  /var/log/filebeat/filebeat

ls /opt | grep 'VBox'

service filebeat restart



# set osquery version
apt-get remove -y osquery

apt-get install -y osquery=2.10.2-1.linux

osqueryi --version



# osquery
service osqueryd stop

rm -rf /var/osquery/osquery.db/*

rm -f /var/log/osquery/*

cp /vagrant/it-compliance.conf /usr/share/osquery/packs/it-compliance.conf

nano /etc/osquery/osquery.conf

service osqueryd restart

tail -f  /var/log/osquery/osqueryd.INFO

jq '.name' /var/log/osquery/osqueryd.results.log | sort | uniq



# kibana
osquery.result.name = pack_it-compliance_deb_packages

osquery.result.columns.platform_like

sudo /usr/share/elasticsearch/bin/elasticsearch-plugin install ingest-geoip

service elasticsearch restart

service filebeat restart




https://launchpad.net/ubuntu/disco/amd64/virtualbox-guest-additions-iso/6.0.4-1

sudo apt-get install -y virtualbox-guest-additions-iso



# Logastash

```
[10-input.conf]
  s3 {
    bucket => "cloudtrail"
    prefix => "folders/CloudTrail/us-east-1/2019/03/27/"
    type => "cloudtrail"
  }
```

```
[20-filter.conf]
  if [type] == "cloudtrail" {
    json  {
     source => "message"
    }

    split {
      field => "Records"
    }
    mutate {
      add_field => { "[@metadata][beat]" => "%{type}" }
      add_field => { "[@metadata][version]" => "6.6.2" }
    }
    geoip {
      source => "[Records][sourceIPAddress]"
      target => "geoip"
      add_tag => [ "cloudtrail-geoip" ]
    }
  }
```
