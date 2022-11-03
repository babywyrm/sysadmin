# BurpSuite SSL Pass Trough Config
Filter out the noise unwanted request capture on burpsuite

## Import
<img src="https://i.ibb.co/Prfr7y4/SSLPass-Trough1.png">

# Another
## FoxyProxy Firefox 
```https://gist.github.com/0xatul/71737250fc77b73ec8a681ccd003c949```

## FoxyProxy Chrome
```https://gist.github.com/FlameOfIgnis/92b01a9969368000d042e6a296441355```

## Greets
- Cans21
- Sec7or Team
- Surabaya Hacker Link


##
##

passthru_.json


```
{
    "proxy":{
        "ssl_pass_through":{
            "automatically_add_entries_on_client_ssl_negotiation_failure":false,
            "rules":[
                {
                    "enabled":true,
                    "host":".*\\.google\\.com",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.gstatic\\.com",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.googleapis\\.com",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.google-analytics\\.com",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.googletagmanager\\.com",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.googletagservices\\.com",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.google\\.co\\.*",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.doubleclick\\.net",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.googleadservices\\.com",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.googlesyndication\\.com",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.googleusercontent\\.com",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.mozilla\\.com",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.mozilla\\.net",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.firefox\\.com",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.bugsnag\\.com",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.yastatic\\.net",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.admetrica\\.ru",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.twimg\\.com",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.yahoo\\.com",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.mozilla\\.org",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.yimg\\.com",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.x-tags\\.net",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.uadexchange\\.com",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.uzone\\.id",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.notifa\\.info",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.cloudfront\\.net",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.indihome\\.co\\.id",
                    "protocol":"any"
                },
                {
                    "enabled":true,
                    "host":".*\\.upoint\\.id",
                    "protocol":"any"
                }
            ]
        }
    }
}
```
