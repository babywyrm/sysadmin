
#
##
https://serverfault.com/questions/1069362/fail2ban-on-centos-7-with-docker-powered-traefik-ban-ok-without-iptables-rule-ad
#
https://gist.github.com/acundari/9bdcf2ba0c0f8a4bf59a21d06da35612
##
#

Fail2ban on CentOS 7 with Docker-powered Traefik ban OK without iptables rule addition
Asked 1 year, 5 months ago
Modified 1 year, 5 months ago
Viewed 699 times

Report this ad

0


I set up a Traefik instance run by Docker engine in Swarm mode with a "classical" configuration (see below, for sake of brevity I only put relevant [to me] parts. Feel free to ask more details if you need so).

Fail2Ban is installed, as well as firewalld (CentOS distribution). So far I put simple filter/jail configuration, mostly for blocking DOS and bruteforce, by watching Traefik access log.

My problem : when I try with Nikto or Hydra, I can see my trying IP been blacklisted :

# fail2ban-client status symfony-auth
Status for the jail: symfony-auth
|- Filter
|  |- Currently failed: 3
|  |- Total failed:     906
|  `- File list:        /var/log/traefik/access.log
`- Actions
   |- Currently banned: 1
   |- Total banned:     2
   `- Banned IP list:   37.19.218.169
But nothing changes on iptables rules part, and I can see the given IP is not blocked. Furthermore, if I try to navigate on website from the banned IP, I can do it, even though it is banned.

I must add that I have 00-firewalld.conf file, with default instructions regarding to actions for this distro:

# cat /etc/fail2ban/jail.d/00-firewalld.conf
# This file is part of the fail2ban-firewalld package to configure the use of
# the firewalld actions as the default actions.  You can remove this package
# (along with the empty fail2ban meta-package) if you do not use firewalld
[DEFAULT]
banaction = firewallcmd-rich-rules[actiontype=<multiport>]
banaction_allports = firewallcmd-rich-rules[actiontype=<allports>]
backend=systemd
Finally, I don't have any time difference, such as stated here.

# tail /var/log/messages
Jul 12 13:28:05 ....
# timedatectl
               Local time: Mon 2021-07-12 13:30:18 UTC
           Universal time: Mon 2021-07-12 13:30:18 UTC
                 RTC time: Mon 2021-07-12 13:30:13
                Time zone: UTC (UTC, +0000)
System clock synchronized: yes
              NTP service: active
          RTC in local TZ: no


So why my banned IP can still reach the target website ? Thanks for yours leads & enlightments.

Snippets
Traefik docker-compose.yml
Logging part

version: "3.3"

services:
  reverse-proxy:
    image: "traefik:v2.4"
    command:
      # Log configuration
      #- "--log.level=DEBUG"
      - "--log.filepath=/var/log/traefik/traefik.log"
      - "--accesslog.filepath=/var/log/traefik/access.log"
     
Volume part :

    # ...
    volumes:
      # To persist certificates
      - traefik-certificates:/letsencrypt
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - /var/log/traefik:/var/log/traefik/
    # ...
Fail2Ban
My filter
/etc/fail2ban/filter.d/my_filter.conf

[Definition]
failregex = ^<HOST>.*"(GET|POST|HEAD).*" (404|444|403|400|301) .*$
ignoreregex =
My jail
[my_jail]
 enabled  = true
 port     = http,https
 filter   = my_filter
 logpath  = /var/log/traefik/access.log
 maxretry = 10
Client status
# fail2ban-client status
Status
|- Number of jail:      2
`- Jail list:   sshd, my_jail
centosconfigurationfail2bandocker-swarm
Share
Improve this question
Follow
asked Jul 12, 2021 at 13:34
nbonniot's user avatar
nbonniot
12777 bronze badges
Add a comment
1 Answer
Sorted by:

Highest score (default)

1


So why my banned IP can still reach the target website?

There may be 3 reasons for that:

your firewalld backend (iptables?) is unsuitable to handle this, see https://github.com/fail2ban/fail2ban/issues/1609#issuecomment-303085942 (or https://github.com/firewalld/firewalld/issues/44#issuecomment-408211978) for details. Shortly, new nftables backend of firewalld can handle this properly, so you may need to switch to this, or ...
This may also lead us to next two reasons (former is more related than the later):

if your network sub-system has some white-listing rules (and I guess so), for instance conntrack rules bypassing already established connections before the chains of fail2ban, then adding the rules to fail2ban tables, rejecting the IP, would not affect this established connections (e. g. in case of keep-alive), only new connections will be rejected then... in this case either ensure to reject connection in web-server after auth-failures, or reorder the chains (chains of fail2ban before the white-listing rules), or kill the connection with extra command in actionban, e.g. ss -K dst "[<ip>]" or conntrack -D -s <ip>, etc. See https://github.com/fail2ban/fail2ban/pull/3018/commits/8f6a8df3a45395620e434fd15b4ede694a1d00aa (or https://github.com/fail2ban/fail2ban/commit/bbfff1828061514e48395a5dbc5c1f9f81625e82) for similar issue with ufw;

because it is dockerized, you have probably to define chain = DOCKER-USER or similar, just action firewallcmd-rich-rules is not suitable for that (don't have parameter chain at all)... Use another banning action (e.g. native net-filters like iptables/ipset or nftables) supporting that.

Anyway you have to check how the incoming traffic (inclusive established) reaches the resulting chains/tables fail2ban creates for the banning of IP, considering all pre-defined chains/tables of docker and firewalld.
Alternatively simply use banning actions for native net-filter sub-systems like iptables+ipset or nftables (e. g. with proper target table for the fail2ban chains, for instance DOCKER-USER instead of INPUT).

Share
Improve this answer
Follow
answered Jul 12, 2021 at 16:05
sebres's user avatar
sebres
97011 gold badge55 silver badges66 bronze badges
Thanks for your remarkably detailled answer. The point was indeed your third one, I totally missd out the multiple chains regarding Iptables. Adding chain = DOCKER-USER made it work without any problem – 
nbonniot
 Jul 13, 2021 at 6:34
