# _check_zonesync_

check_zonesync is a nagios plugin which can determine whether zones are
replicated properly between master and slave DNS servers and if master/masters
have properly loaded zones/are servering the most recent version of zone/zones.

## Installation

In order to run check_zonesync you need to following dependencies installed:
- pymisc (https://github.com/vespian/pymisc)
- python >=3.2 (not tested on earlier versions)
- python3-yaml
- python3-dnspython

You can also use debian packaging rules from debian/ directory to build a deb
package. It requires pybuild debian build system for Python. More details can
be found here: https://wiki.debian.org/Python/Pybuild

## Operation

The tool assumes that for each zone, file pointed by zonedata argument has the
correct and the most up2date zone information. It is parsed using dnspython
python module and stored in scripts memory. Then, script connects first to DNS
masters defined in his config file and requests AXFR transfer. If the data rece-
ived from master differs from the one obtained from file, script assumes that
slaves do not have correct data either and returns warning/critical message to
the monitoring system. If the data is correct, the script requests AXFR zone
transfers from slaves as well. If the data is also in sync then the script
concludes that DNS servers are serving correct data.

Worth noting is the fact that SOA differences result in warning state, and any
other error condition ends with critical. This is due to the fact that SOA header
differences are not mission critical, whereas things like differing/missing
CNAME records, failed AXFR tranfer,  unreachable DNS server are.

The script fully supports TSIG zone signing, so it is possible to check zone
replication/synchronization even if serwers are authenticating the transmission.

### Commandline/debugging
The tool has built in help:

```
root@adns:/etc/bind# check-zonesync -h
usage: check-zonesync [-h] [--version] -c CONFIG_FILE [-v] [-s]

Zone replication synchronization check.

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -c CONFIG_FILE, --config-file CONFIG_FILE
                        Location of the configuration file
  -v, --verbose         Provide extra logging messages.
  -s, --std-err         Log to stderr instead of syslog

Author: Pawel Rozlach <pawel.rozlach@brainly.com>
```

At minimum, the script needs to know where it can find the config file. The
'-v' and '-s' options are usefull only during debugging and verifying the
alert raised by the plugin.

### Config file
As mentioned earlier the script uses the config file which define what and how
should be checked. Same config file can be found below:

```
---
lockfile: /tmp/check-zonesync.lock
timeout: 3

zones:
  test1.zone.pl:
    zonehosts:
        master1:
            ip: 1.2.3.4
            port: 54
            key-id: master1-slave-key
            key-data: 8Y82bUZAy+izCckwxYUiMF1yzngCL8vZbNWydhYupE3U6KOcfAkcjm5xn42ZhJgYkwtTcqOT8rrsxop7SLe6vQ==
            key-algo: hmac-sha512
            master: true
        master2:
            ip: 1.2.3.5
            key-id: master2-slave-key
            key-data: 9DpVfo7ossbLvLSIvZjz0Zw0+N/kd+c6Z/c5z1SajpFsTYMDaktsujTLmDJ7zDp8MFDU1M5Hax2+p5xS+mfBLw==
            key-algo: hmac-sha512
            master: true
        slavehost1:
            ip: 2.3.4.5
        slavehost2:
            ip: 2.3.4.6
            key-id: slavehost2-slave-key
            key-data: YUsVB42q8QxW/t1KINeM8CAo0A63j3LTlNLPZ8nqGXMUL/rArk17CfjpYDgmWlIGloYNs3UYkUibWztQiK9lEg==
            key-algo: hmac-sha512
        slavehost3:
            ip: 2.3.4.7
            key-id: slavehost3-slave-key
            key-data: msTrUNoF7BHApvSQkgEyn8v3LVr+/ssJVUFlytDiRHgZz6RmhVCl1FfIb51rXCcGb190V8ZAuVvLFbWJ0W/n8w==
            key-algo: hmac-sha512
    zonedata: /tmp/example.com.zone
```

The meaning of the fields is as follows:
- *lockfile*(mandatory) - the file that the script will use for advisory locking. Only one
instance of the script should be active at any given time.
- *timeout*(mandatory) - time after which script will abort it's operation and terminate.
A message to the monitoring system will still be sent to warn the user.
- *zones*(mandatory) - a hash with zone names as keys, which contains all the data required
to verify the zone synchroniztion. Each zone has following options available:
    - *zonedata*(mandatory) - the path to a file that contains correct DNS zone data.
    - *zonehosts*(mandatory) - peers(masters/slaves, not matter if stealth or not) that
    serve given domain. Peer's name should be meaningfull, but it is not used
    by the script to connect to the named daemon.

Each *zonehosts* entry has following parameters:
- *ip*(mandatory) - IP address of the host that the plug should connect to in order to
verify the correctness of the zone.
- *port*(optional) - the port that should be used when connecting to the zone hosts. By
default it is '53'.
- *master*(optional) - defines if the host is master or slave for given zone.
By default the host is a slave to a domain.
- *key-id*(optional) - id of the TSIG key that should be sent to the server while requiring
zone transfer
- *key-data*(optional) - the base64 encoded TSIG key itself
- *key-algo*(optional) - TSIG algorithm that should be used.

## Additional information
The script's source is well documented - please consult it in case of any
ambiguities

## Testing

FIXME - write more tests!

Currenlty the unittest python library is used to perform all the testing. In
test/ directory you can find:
- modules/ - modules used by unittests
- moduletests/ - the unittests themselves
- fabric/ - sample input files and test certificates temporary directories
- output_coverage_html/ - coverage tests results in a form of an html webpage

Unittests can be started either by using *nosetest* command:

```
(venv) vespian@mop:check_growth/ (master) $ python3 `which nosetests`                                                                                          [17:33:15]
........
----------------------------------------------------------------------
Ran 1 tests in 0.349s

OK
```

or by issuing the *run_tests.py* command:

```
(venv) vespian@mop:check_growth/ (master) $ ./run_tests.py                                                                                                     [17:33:21]
........
----------------------------------------------------------------------
Ran 8 tests in 0.258s

OK
```

The difference is that the *run_tests.py* takes care of generating coverage
reports for you.


## Author Information

This script has been created by Pawel Rozlach during his work for Brainly.com,
and then opensourced by the company on Apache 2.0 license. Please check the
![LICENSE](LICENSE) file for more details.
