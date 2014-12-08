#!/usr/bin/env python3
# Copyright (c) 2014 Brainly.com sp. z o.o.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

# Imports:
from collections import namedtuple, defaultdict
from pymisc.monitoring import ScriptStatus
from pymisc.script import RecoverableException, ScriptConfiguration, ScriptLock
from pymisc.script import ScriptTimeout, FatalException
import argparse
import dns.query
import dns.tsigkeyring
import dns.update
import dns.zone
import logging
import logging.handlers as lh
import os
import re
import sys

# Defaults:
LOCKFILE_LOCATION = './'+os.path.basename(__file__)+'.lock'
CONFIGFILE_LOCATION = './'+os.path.basename(__file__)+'.conf'


class ZoneTransferFailed(RecoverableException):
    """
    A catch-all exception for zone transfer failures.
    """
    pass


class ZoneParseFailed(RecoverableException):
    """
    A catch-all exception for zone file parsing failures.
    """
    pass


def parse_command_line():
    parser = argparse.ArgumentParser(
        description='Zone replication synchronization check.',
        epilog="Author: Pawel Rozlach <pawel.rozlach@brainly.com>",
        add_help=True,)
    parser.add_argument(
        '--version',
        action='version',
        version='1.0')
    parser.add_argument(
        "-c", "--config-file",
        action='store',
        required=True,
        help="Location of the configuration file")
    parser.add_argument(
        "-v", "--verbose",
        action='store_true',
        required=False,
        help="Provide extra logging messages.")
    parser.add_argument(
        "-s", "--std-err",
        action='store_true',
        required=False,
        help="Log to stderr instead of syslog")

    args = parser.parse_args()
    return {'std_err': args.std_err,
            'verbose': args.verbose,
            'config_file': args.config_file,
            }


def _verify_host_data(host_hash, zone, host_name):
    """
    Check if hosts conifguration is sane.

    Check if hosts configuration follows some basic rules on which the script's
    main loop depends.

    Args:
        host_hash: A hash containing host's configuration. Fields are as follows:
            ip: mandatory. IP address of the host
            port: optional, default is 53. Port to use while connecting.
            key-id: optional. The ID of the key that should be send to the host.
            key-data: optional. The TSIG key itself.
            master: optional, default is False. Flag depicting whether host is
                master for the zone or not.
        zone: The zone to which host's configuration belongs to.
        host_name: The hostname of the host.

    Returns:
        A string containing description of problems found or an empty string
        if there are none.
    """
    msg = []

    if 'ip' in host_hash:
        ip = host_hash['ip']
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            msg.append('Zonehost {0} from zone {1} has malformed IP: {2}.'.format(
                host_name, zone, ip))
    else:
        msg.append('Zonehost {0} from zone {1} '.format(zone) +
                   'does not have mandatory "ip" field.')

    if 'port' in host_hash:
        port = host_hash['port']
        if not isinstance(port, int) or port < 1:
            msg.append('Zonehost {0} of zone {1} '.format(host_name, zone) +
                       'has malformed port: {0}.'.format(port))

    if "key-id" in host_hash or "key-data" in host_hash:
        if not ("key-id" in host_hash and "key-data" in host_hash):
            msg.append('Zonehost {0} from zone {1} '.format(host_name, zone) +
                       'should have both "key-id" and "key-data" keys ' +
                       'defined or none of them.')
        else:
            if not re.match(r"^[a-zA-Z0-9-\.]+$", host_hash['key-id']):
                msg.append('Zone {0}, zonekey for host {1}'.format(zone, host_name) +
                           ' has invalid "id" entry: {0}.'.format(
                           host_hash['key-id']))
            if not re.match(
                    "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
                    host_hash['key-data']):
                msg.append('Zone {0}, zonekey for host {1}'.format(zone, host_name) +
                           ' has non-base64 "data" entry.')

    return msg


def _verify_conf(conf_hash):
    """
    Check if script configuration is sane.

    This function takes care of checking if the script configuration is
    logically correct.

    Args:
        conf_hash: A hash containing whole configuration, as defined in config
            file.

    Returns:
        A list of errors/issues found in the configuration, or an empty list
        if the configuration is OK.
    """
    msg = []

    timeout = conf_hash['timeout']
    zones = conf_hash['zones']

    if timeout < 1:
        msg.append('Timeout should be >1.')

    if len(zones) < 1:
        msg.append('There should be at least one zone to test.')

    for zone in zones:
        # Zone name has correct format
        if not re.match(r'^(([a-z0-9]\-*[a-z0-9]*){1,63}\.?){1,255}$', zone):
            msg.append('Zone {0} is not a valid domain name.'.format(zone))

        # Small shortcut:
        def is_master(hostname):
            return 'master' in zones[zone]['zonehosts'][hostname] and \
                zones[zone]['zonehosts'][hostname]['master'] is True

        masters = [x for x in zones[zone]['zonehosts'] if is_master(x)]

        # There is at least one master handling this zone:
        if not len(masters):
            msg.append('Zone {0} does not contain any masters.'.format(
                zone))
            continue  # No point in checking this zone further

        # Verify individual entries:
        for zonehost in zones[zone]['zonehosts']:
            msg.extend(_verify_host_data(zones[zone]['zonehosts'][zonehost],
                       zone, zonehost))

        # There should be at least:
        # 1) one master and "zone_data" section specified in the config file
        # 2) two or more hosts if "zone_data" was not provided
        if 'zonedata' not in zones[zone] and len(zones[zone]['zonehosts']) < 2:
            msg.append('Zone {0} should have at least'.format(zone) +
                       ' two masters or a slave and a master if zone_data' +
                       ' is not provided')

        # Verify zone's zonedata
        if 'zonedata' in zones[zone]:
            if not (os.path.exists(zones[zone]['zonedata'])
                    and os.access(zones[zone]['zonedata'], os.R_OK)):
                msg.append("Zone's {0} zonedata file is not".format(zone) +
                           "accessible or cannot be read")
    return msg


def fetch_domain_data(zone_name=None, zone_file=None, host=None, port=None,
                      key_id=None, key_data=None, key_algo=None):
    """
    Fetch domain data via AXFR query, or from a file.

    This function fetches domain data either via AXFR query or from a file and
    parses it dnspython's "zone" object. If the zone key data is provided, then
    the AXFR request is signed.

    Args:
        host: An IP address of the host to query for DNS data.
        path: The path to the file that contains zone data.
        key_id: An identification string for TSIG signing key.
        key_data: A TSIG signing key which should be used during
            query.
        key_algo: Agorithm to use while signing AXFR transfer

    Returns:
        A dnspython's zone object.

    Raises:
        ZoneTransferFailed: An error occured while requesting for zone
            transfer.
        ZoneParseFailed: An error occured while parsing zone data file.
        FatalException: Incorect command line arguments were supplied.
    """
    if zone_file and not (host or port or key_id or key_data or key_algo):
        try:
            zone = dns.zone.from_file(zone_file, origin=zone_name)
        except dns.exception.DNSException as e:
            raise ZoneParseFailed() from e
    elif not zone_file and \
        ( host and not (key_id or key_data or key_algo)) or \
        ( host and key_id and key_data and key_algo):
        try:
            if key_id:
                keyring = dns.tsigkeyring.from_text({key_id: key_data})
                keyname = key_id
                keyalgo = key_algo
            else:
                keyring = None
                keyname = None
                keyalgo = None
            zone = dns.zone.from_xfr(dns.query.xfr(where=host,
                                                   zone=zone_name,
                                                   port=port,
                                                   keyring=keyring,
                                                   keyname=keyname,
                                                   keyalgorithm=keyalgo
                                                   ))
        except dns.exception.DNSException as e:
            raise ZoneTransferFailed() from e
    else:
        raise FatalException("Function arguments are malformed: {0}".format(
                             [zone_file, host, port, key_id, key_data]))

    return zone


def compare_domain_data(zone_correct, zone_tested):
    """
    Compare two zones.

    This function compares two dnspython's zone objects, treating one as
    a correct data and the other as a tested data. The differences (if any)
    are returned in a human readable form and as an agregate.

    Args:
        zone_correct: A dnspython's zone object which should be treated
            as correct.
        zone_tested: A dnspython's zone object which should be checked
            for correctness.

    Returns:
        A named tuple containing:
        - a set with abbreviated list of differences (just the record
            types)
        - a list containing a full decription of differences.

        Both lists are empty if zones are identical.

        For example, return value when data differes:
            ZoneDiff(full=["SOA record differs: 1234->4321",
                           "a.example.com CNAME record is missing",
                           "b.example.com A record is redundant",
                           ...],
                     record_types=set(["SOA", "CNAME", "A"]))
        ,return value where both hashes where identical:
        ZoneDiff(full=[], record_types=set([]))
    """
    ret = namedtuple('ZoneDiff', ['full', 'record_types'])
    ret.full = []
    ret.record_types = set([])

    # Check for missing and changed items:
    for record_name, node in zone_correct.items():
        rdatasets = node.rdatasets
        for rdataset in rdatasets:
            record_type = dns.rdatatype.to_text(rdataset.rdtype)
            for rdata in rdataset:
                tmp = False  # == differs/missing
                node_tested = zone_tested.get_node(record_name)
                if node_tested is None:
                    # All records for this "record_name" are missing:
                    tmp = True
                else:
                    rdatasets_tested = node_tested.rdatasets
                if tmp or rdataset not in rdatasets_tested:
                    # All records for this "record_name" and "record_type" are
                    # missing:
                    tmp = True
                else:
                    rdataset_tested = node_tested.find_rdataset(rdataset.rdclass,
                                                                rdataset.rdtype)
                if tmp or rdata not in rdataset_tested:
                    # This particular entry is missing:
                    ret.record_types.add(record_type)
                    ret.full.append("{0} '{1}':{2} is missing".format(record_type,
                                    record_name, str(rdata)))
                else:
                    # Entry has not changed:
                    logging.debug("{0} '{1}' entry OK: {2}".format(
                                  record_type, record_name,
                                  rdataset.to_text().replace('\n', ', ')))

    # Check for redundant items:
    for record_name, node in zone_tested.items():
        rdatasets = node.rdatasets
        for rdataset in rdatasets:
            record_type = dns.rdatatype.to_text(rdataset.rdtype)
            for rdata in rdataset:
                tmp = False  # == redundant
                node_correct = zone_correct.get_node(record_name)
                if node_correct is None:
                    # All records for this "record_name" are redundant:
                    tmp = True
                else:
                    rdatasets_correct = node_correct.rdatasets
                if tmp or rdataset not in rdatasets_correct:
                    # All records for this "record_name" and "record_type" are
                    # redundant:
                    tmp = True
                else:
                    rdataset_correct = node_correct.find_rdataset(rdataset.rdclass,
                                                                 rdataset.rdtype)
                if tmp or rdata not in rdataset_correct:
                    ret.record_types.add(record_type)
                    ret.full.append("{0} '{1}':{2} is redundant".format(
                                    record_type, record_name, str(rdata)))
                else:
                    # "Entry correct" case has already been covered:
                    pass

    return ret


def main(config_file, std_err=False, verbose=True):
    """
    Main function of the script

    Args:
        config_file: file path of the config file to load
        std_err: whether print logging output to stderr
        verbose: whether to provide verbose logging messages
    """

    try:
        # Configure logging:
        fmt = logging.Formatter('check-zonesync[%(process)d] %(levelname)s: ' +
                                '%(message)s')
        logger = logging.getLogger()
        if verbose:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
        if std_err:
            handler = logging.StreamHandler()
        else:
            handler = lh.SysLogHandler(address='/dev/log',
                                       facility=lh.SysLogHandler.LOG_USER)
        handler.setFormatter(fmt)
        logger.addHandler(handler)

        logger.debug("{0} is starting, ".format(os.path.basename(__file__)) +
                     "command line arguments: " +
                     "config_file={0}, ".format(config_file) +
                     "std_err={0}, ".format(std_err) +
                     "verbose={0}, ".format(verbose)
                     )

        ScriptConfiguration.load_config(config_file)

        logger.debug("Loaded configuration: " +
                     str(ScriptConfiguration.get_config())
                     )

        # Some basic sanity checking:
        conf_issues = _verify_conf(ScriptConfiguration.get_config())
        if conf_issues:
            logging.debug("Configuration problems:\n\t" +
                          '\n\t'.join(conf_issues))
            ScriptStatus.notify_immediate('unknown',
                                          "Configuration file contains errors: " +
                                          ' '.join(conf_issues))

        # Initialize reporting to monitoring system:
        ScriptStatus.initialize(nrpe_enabled=True)

        # Make sure that we are the only ones running on the server:
        ScriptLock.init(ScriptConfiguration.get_val('lockfile'))
        ScriptLock.aqquire()

        # Set timeout:
        ScriptTimeout.set_timeout(
            ScriptConfiguration.get_val('timeout'),
            ScriptStatus.notify_immediate,
            args=['unknown', "Timed out after {0} seconds".format(
                ScriptConfiguration.get_val('timeout'))],
            kwargs={},
            )

        # Do some real work...
        zones = ScriptConfiguration.get_val('zones')
        for zone in zones:
            logger.info("Checking zone {0}".format(zone))

            if 'zonedata' in zones[zone]:
                try:
                    zonedata_correct = fetch_domain_data(zone_name=zone,
                                                         zone_file=zones[zone]['zonedata'])
                except ZoneParseFailed as e:
                    ScriptStatus.update("critical", "Failed to load zone file " +
                                        "for zone {0}: {1}.".format(zone, str(e)))
                    # There is no point in continuing
                    continue
                else:
                    logger.info("Correct zone data taken from zone file")
            else:
                zonedata_correct = None

            # Small shortcut:
            def is_master(hostname):
                return 'master' in zones[zone]['zonehosts'][hostname] and \
                    zones[zone]['zonehosts'][hostname]['master'] is True

            # Make sure master hosts come first, and that they are in sorted
            # order:
            zonehosts = sorted([x for x in zones[zone]['zonehosts'] if
                                is_master(x)])

            zonehosts.extend(sorted([x for x in zones[zone]['zonehosts'] if
                                     not is_master(x)]))

            logger.debug("Ordered list of zonehosts: {0}".format(zonehosts))

            # Used to provie some nice message if everything is OK
            zoneok_flag = True

            for zonehost in zonehosts:
                ip = zones[zone]['zonehosts'][zonehost]['ip']
                if 'port' in zones[zone]['zonehosts'][zonehost]:
                    port = zones[zone]['zonehosts'][zonehost]['port']
                else:
                    port = 53
                if 'key-id' in zones[zone]['zonehosts'][zonehost]:
                    key_id = zones[zone]['zonehosts'][zonehost]['key-id']
                    key_data = zones[zone]['zonehosts'][zonehost]['key-data']
                    key_algo = zones[zone]['zonehosts'][zonehost]['key-algo']
                else:
                    key_id = None
                    key_data = None
                    key_algo = None
                try:
                    zonedata_cur = fetch_domain_data(zone_name=zone,
                                                     host=ip,
                                                     port=port,
                                                     key_id=key_id,
                                                     key_data=key_data,
                                                     key_algo=key_algo)
                except ZoneTransferFailed as e:
                    ScriptStatus.update("critical", "Failed to perform AXFR " +
                                        "transfer of zone {0} ".format(zone) +
                                        "from server {0}".format(zonehost))
                    zoneok_flag = False
                    continue

                if not zonedata_correct:
                    if is_master(zonehost):
                        logger.info("Correct zone data taken from master host " +
                                    "{0}.".format(zonehost))
                        zonedata_correct = zonedata_cur
                        continue
                    else:
                        # We already reached slaves in zonehosts list and we
                        # still do not have correct data. Let's fail the zone
                        # and move to the next one.
                        ScriptStatus.update("critical", "Zone {0} ".format(zone) +
                                            "does not have usable correct " +
                                            "zonedata sources.")
                        zoneok_flag = False
                        break

                zonedata_diff = compare_domain_data(zonedata_correct, zonedata_cur)
                # ZoneDiff(full=[], record_types=set([]))
                if len(zonedata_diff.record_types) > 0:
                    # Treat diferences in serial as just a "warning", everything
                    # else as "critical".
                    if zonedata_diff.record_types == set(["SOA", ]):
                        severity = "warn"
                    else:
                        severity = "critical"

                    ScriptStatus.update(severity, "Host {0} ".format(zonehost) +
                                        "is serving stale data for domain " +
                                        "{0}: {1} records differ.".format(
                                            zone, ','.join(zonedata_diff.record_types)))

                    msg = "Detailed differences between zonedata_correct " +\
                          "and the data received from host {0}:\n\t".format(
                              zonehost) + "\n\t".join(zonedata_diff.full)
                    logger.warn(msg)

                    zoneok_flag = False

            if zoneok_flag is True:
                ScriptStatus.update("ok", "Zone {0} is in sync on ".format(zone) +
                                          "hosts: {0}.".format(",".join(zonehosts)))

        # Send gathered data to the monitoring system.
        ScriptTimeout.clear_timeout()
        ScriptLock.release() # I do not like it, but ScriptStatus.notify_agregated
                             # calls sys.exit() when configured with Nagios.
        ScriptStatus.notify_agregated()

    except RecoverableException as e:
        msg = str(e)
        logging.critical(msg)
        ScriptLock.release()
        ScriptStatus.notify_immediate('unknown', msg)
        sys.exit(1)
    except AssertionError as e:
        # Unittests require it:
        raise
    except Exception as e:
        msg = "Exception occured: {0}".format(e.__class__.__name__)
        logging.exception(msg)
        print(msg)  # We can use notify immediate here :(
        ScriptLock.release()
        sys.exit(3)
