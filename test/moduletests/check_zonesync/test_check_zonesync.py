#!/usr/bin/env python3
# Copyright (c) 2014 Brainly.com sp. z o.o.
# Copyright (c) 2013 Spotify AB
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

# Global imports:
import copy
import mock
import os
import pymisc
import sys
import unittest
import dns
from pymisc.script import ScriptConfiguration
from collections import namedtuple

# To perform local imports first we need to fix PYTHONPATH:
pwd = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.abspath(pwd + '/../../modules/'))

# Local imports:
import file_paths as paths
import check_zonesync


class TestArgumentParsing(unittest.TestCase):
    def test_verbose_flag(self):
        ret = check_zonesync.parse_command_line(script_name="test-scriptname",
                                                args=["-c", "/path/to/test",
                                                      "--verbose"])

        self.assertEqual({'config_file': '/path/to/test',
                          'std_err': False,
                          'verbose': True},
                         ret)

    def test_stderr_flag(self):
        ret = check_zonesync.parse_command_line(script_name="other-scriptname",
                                                args=["-c", "/path/to/test", "-s"])

        self.assertEqual({'config_file': '/path/to/test',
                          'std_err': True,
                          'verbose': False},
                         ret)

    def test_minimal_invocation(self):
        ret = check_zonesync.parse_command_line(script_name="other-scriptname",
                                                args=["-c", "/path/to/other/test"])

        self.assertEqual({'config_file': '/path/to/other/test',
                          'std_err': False,
                          'verbose': False},
                         ret)


@mock.patch('dns.tsigkeyring.from_text')
@mock.patch('dns.zone.from_xfr')
@mock.patch('dns.query.xfr')
class TestZoneDataFetch(unittest.TestCase):
    def test_input_argument_sanity_checking(self, DNSQueryXfrMock,
                                            DNSZoneFromXfrMock,
                                            DNSKeyringFromTextMock):

        with self.assertRaises(pymisc.script.FatalException):
            check_zonesync.fetch_domain_data(zone_file="/path/to/zonefile",
                                             host="example.com")

    def test_zone_file_parsing(self, DNSQueryXfrMock,
                               DNSZoneFromXfrMock,
                               DNSKeyringFromTextMock):

        with self.assertRaises(check_zonesync.ZoneParseFailed):
            check_zonesync.fetch_domain_data(zone_file=paths.TEST_ZONE_BAD)

        check_zonesync.fetch_domain_data(zone_file=paths.TEST_ZONE_GOOD)

    def test_zone_axfr_parsing_with_key(self, DNSQueryXfrMock,
                                        DNSZoneFromXfrMock,
                                        DNSKeyringFromTextMock):

        DNSKeyringFromTextMock.return_value = "test-keyring"

        check_zonesync.fetch_domain_data(host="example-server.com",
                                         zone_name="example.com",
                                         port=53,
                                         key_id="example.com-key_id",
                                         key_data="1234567890",
                                         key_algo="sample-algo",
                                         )
        DNSQueryXfrMock.assert_called_once_with(zone='example.com',
                                                keyalgorithm='sample-algo',
                                                keyring='test-keyring',
                                                where='example-server.com',
                                                keyname='example.com-key_id',
                                                port=53)

    def test_zone_axfr_parsing_without_key(self, DNSQueryXfrMock,
                                           DNSZoneFromXfrMock,
                                           DNSKeyringFromTextMock):

        check_zonesync.fetch_domain_data(host="example-server.com",
                                         zone_name="example.com",
                                         port=53,
                                         )
        DNSQueryXfrMock.assert_called_once_with(zone='example.com',
                                                where='example-server.com',
                                                port=53,
                                                keyalgorithm=None,
                                                keyring=None,
                                                keyname=None,)


class TestZoneComparing(unittest.TestCase):
    def setUp(self):
        self.reference_zone = dns.zone.from_file(paths.TEST_ZONE_GOOD)

    def test_zones_are_the_same(self):
        test_zone = dns.zone.from_file(paths.TEST_ZONE_GOOD)
        ret = check_zonesync.compare_domain_data(self.reference_zone, test_zone)
        self.assertEqual(ret.record_types, set([]))
        self.assertEqual(ret.full, [])

    def test_soa_differs(self):
        test_zone = dns.zone.from_file(paths.TEST_ZONE_GOOD_SOA_DIFFERS)
        ret = check_zonesync.compare_domain_data(self.reference_zone, test_zone)
        self.assertEqual(ret.record_types, set(["SOA"]))
        self.assertEqual(len(ret.full), 2)

    def test_records_missing(self):
        test_zone = dns.zone.from_file(paths.TEST_ZONE_GOOD_DELETED_RECORD)
        ret = check_zonesync.compare_domain_data(self.reference_zone, test_zone)
        self.assertEqual(ret.record_types, set(["CNAME"]))
        self.assertEqual(len(ret.full), 1)

    def test_records_changed(self):
        test_zone = dns.zone.from_file(paths.TEST_ZONE_GOOD_CHANGED_RECORD)
        ret = check_zonesync.compare_domain_data(self.reference_zone, test_zone)
        self.assertEqual(ret.record_types, set(["A"]))
        self.assertEqual(len(ret.full), 2)

    def test_records_added(self):
        test_zone = dns.zone.from_file(paths.TEST_ZONE_GOOD_ADDED_RECORD)
        ret = check_zonesync.compare_domain_data(self.reference_zone, test_zone)
        self.assertEqual(ret.record_types, set(['MX']))
        self.assertEqual(len(ret.full), 1)


class TestHostDataVerification(unittest.TestCase):
    def setUp(self):
        self.host_name = "example-host"
        self.zone = "example.com"
        self.hash = {"ip": "1.2.3.4",
                     "port": 53,
                     "key-id": "example-key",
                     "key-data": "1234567890abcdef",
                     "master": True,
                     }

    def test_verify_host_data_correct(self):
        msg = check_zonesync._verify_host_data(host_hash=self.hash,
                                               zone=self.zone,
                                               host_name=self.host_name)
        self.assertEqual(msg, [])

    def test_verify_host_data_bad_ip(self):
        self.hash["ip"] = "1000.1.2.3.4"
        msg = check_zonesync._verify_host_data(host_hash=self.hash,
                                               zone=self.zone,
                                               host_name=self.host_name)
        self.assertEqual(len(msg), 1)

    def test_verify_host_data_missing_ip(self):
        del self.hash["ip"]
        msg = check_zonesync._verify_host_data(host_hash=self.hash,
                                               zone=self.zone,
                                               host_name=self.host_name)
        self.assertEqual(len(msg), 1)

    def test_verify_host_data_malformed_port(self):
        self.hash["port"] = "53."
        msg = check_zonesync._verify_host_data(host_hash=self.hash,
                                               zone=self.zone,
                                               host_name=self.host_name)
        self.assertEqual(len(msg), 1)

    def test_verify_host_data_incomplete_key_set(self):
        del self.hash["key-data"]
        msg = check_zonesync._verify_host_data(host_hash=self.hash,
                                               zone=self.zone,
                                               host_name=self.host_name)
        self.assertEqual(len(msg), 1)

    def test_verify_host_data_without_keys(self):
        del self.hash["key-id"]
        del self.hash["key-data"]
        msg = check_zonesync._verify_host_data(host_hash=self.hash,
                                               zone=self.zone,
                                               host_name=self.host_name)
        self.assertEqual(msg, [])

    def test_verify_host_data_malformed_key_id(self):
        self.hash["key-id"] = 'this is not a proper key'
        msg = check_zonesync._verify_host_data(host_hash=self.hash,
                                               zone=self.zone,
                                               host_name=self.host_name)
        self.assertEqual(len(msg), 1)

    def test_verify_host_data_malformed_key_data(self):
        self.hash["key-data"] = 'aasfasdfdasf-asdfdas dasf'
        msg = check_zonesync._verify_host_data(host_hash=self.hash,
                                               zone=self.zone,
                                               host_name=self.host_name)
        self.assertEqual(len(msg), 1)


class TestConfigurationVerification(unittest.TestCase):
    def setUp(self):
        # Load test configuration
        ScriptConfiguration.load_config(paths.TEST_CONFIG_FILE)
        self.conf_hash = ScriptConfiguration.get_config()

        self.mocks = {}
        for patched in ['check_zonesync._verify_host_data',
                        'os.access',
                        'os.path.exists', ]:
            patcher = mock.patch(patched)
            self.mocks[patched] = patcher.start()
            self.addCleanup(patcher.stop)

        self.mocks["check_zonesync._verify_host_data"].return_value = []
        self.mocks["os.access"].return_value = True
        self.mocks["os.path.exists"].return_value = True

    def test_proper_configuration(self):
        msg = check_zonesync._verify_conf(self.conf_hash)
        self.assertEqual(msg, [])

    def test_malformed_timeout(self):
        self.conf_hash['timeout'] = 'not an integer'

        msg = check_zonesync._verify_conf(self.conf_hash)
        self.assertEqual(len(msg), 1)

    def test_empty_zone_list(self):
        self.conf_hash['zones'] = {}

        msg = check_zonesync._verify_conf(self.conf_hash)
        self.assertEqual(len(msg), 1)

    def test_malformed_zone_name(self):
        self.conf_hash['zones']['a bad zone'] = self.conf_hash[
            'zones'].pop('test1.zone.pl')

        msg = check_zonesync._verify_conf(self.conf_hash)
        self.assertEqual(len(msg), 1)

    def test_zone_without_masters(self):
        del self.conf_hash['zones']['test1.zone.pl']['zonehosts']['master1']
        del self.conf_hash['zones']['test1.zone.pl']['zonehosts']['master2']

        msg = check_zonesync._verify_conf(self.conf_hash)
        self.assertEqual(len(msg), 1)

    def test_zone_without_datafile(self):
        del self.conf_hash['zones']['test1.zone.pl']['zonedata']
        del self.conf_hash['zones']['test1.zone.pl']['zonehosts']['master1']
        # Removing slaves is also necessary
        del self.conf_hash['zones']['test1.zone.pl']['zonehosts']['slavehost1']
        del self.conf_hash['zones']['test1.zone.pl']['zonehosts']['slavehost2']
        del self.conf_hash['zones']['test1.zone.pl']['zonehosts']['slavehost3']

        msg = check_zonesync._verify_conf(self.conf_hash)
        self.assertEqual(len(msg), 1)

    def test_zone_file_does_not_exists(self):
        self.mocks["os.path.exists"].return_value = False

        msg = check_zonesync._verify_conf(self.conf_hash)
        self.assertEqual(len(msg), 1)


class TestMainLogic(unittest.TestCase):
    def setUp(self):

        self.mocks = {}
        for patched in ['check_zonesync.ScriptStatus',
                        'check_zonesync.ScriptTimeout',
                        'check_zonesync.ScriptLock',
                        'check_zonesync._verify_conf',
                        'check_zonesync.fetch_domain_data',
                        'check_zonesync.compare_domain_data',
                        'check_zonesync.sys.exit',
                        'logging.error',
                        'logging.info',
                        'logging.warn', ]:
            patcher = mock.patch(patched)
            self.mocks[patched] = patcher.start()
            self.addCleanup(patcher.stop)

        def terminate_script(exit_status):
            raise SystemExit(exit_status)
        self.mocks["check_zonesync.sys.exit"].side_effect = terminate_script
        self.mocks["check_zonesync._verify_conf"].return_value = []

        def terminate_script(*unused):
            raise SystemExit(216)
        self.mocks["check_zonesync.ScriptStatus"].notify_immediate.side_effect = \
            terminate_script
        self.mocks["check_zonesync.ScriptStatus"].notify_agregated.side_effect = \
            terminate_script
        self.mocks["check_zonesync.fetch_domain_data"].return_value = "fooBar"

        self.zonediff_ret = namedtuple('ZoneDiff', ['full', 'record_types'])
        self.zonediff_ret.record_types = set()
        self.zonediff_ret.full = []
        self.mocks["check_zonesync.compare_domain_data"].return_value = self.zonediff_ret

    def test_all_ok(self):
        with self.assertRaises(SystemExit):
            check_zonesync.main(paths.TEST_CONFIG_FILE)
        self.assertFalse(
            self.mocks["check_zonesync.ScriptStatus"].notify_immediate.called)
        self.mocks["check_zonesync.ScriptStatus"].notify_agregated.assert_called_once_with()

    def test_configuration_issues(self):
        self.mocks["check_zonesync._verify_conf"].return_value = \
            ["There is a problem with configuration"]

        with self.assertRaises(SystemExit):
            check_zonesync.main(paths.TEST_CONFIG_FILE)

        self.mocks["check_zonesync.ScriptStatus"].notify_immediate.assert_called_once_with(
            'unknown',
            'Configuration file contains errors: There is a problem with configuration')

    def test_zone_data_parsing_problems(self):
        def raise_parserror(zone_name, zone_file, *unused_p, **unused_kw):
            if not unused_p and not unused_kw:
                raise check_zonesync.ZoneParseFailed
            else:
                # With this test data it should not happen
                self.fail("check_zonesync.fetch_domain_data called with non-file"
                          " arguments")
        self.mocks["check_zonesync.fetch_domain_data"].side_effect = raise_parserror

        with self.assertRaises(SystemExit):
            check_zonesync.main(paths.TEST_CONFIG_FILE)

        self.assertFalse(self.mocks["check_zonesync.ScriptStatus"].notify_immediate.called)
        self.mocks["check_zonesync.ScriptStatus"].notify_agregated.assert_called_once_with()
        self.mocks["check_zonesync.ScriptStatus"].update.assert_has_calls(
            mock.call('critical', 'Failed to load zone file for zone test1.zone.pl: .'))

    def test_axfr_zone_transfer_problems(self):
        def raise_transfererror(zone_name=None,
                                zone_file=None,
                                host=None,
                                port=None,
                                key_id=None,
                                key_data=None,
                                key_algo=None):
            if zone_name == 'test1.zone.pl' and \
                    zone_file == '/tmp/example.com.zone':
                # We are not testing this here:
                pass
            else:
                raise check_zonesync.ZoneTransferFailed()
        self.mocks["check_zonesync.fetch_domain_data"].side_effect = raise_transfererror

        with self.assertRaises(SystemExit):
            check_zonesync.main(paths.TEST_CONFIG_FILE)

        self.assertFalse(self.mocks["check_zonesync.ScriptStatus"].notify_immediate.called)
        self.mocks["check_zonesync.ScriptStatus"].notify_agregated.assert_called_once_with()
        all_updates_were_critical = all([x[0][0] == 'critical'
            for x in self.mocks["check_zonesync.ScriptStatus"].update.call_args_list])
        self.assertTrue(
            all_updates_were_critical and
            len(self.mocks["check_zonesync.ScriptStatus"].update.call_args_list) > 0)

    def test_no_masterhost_and_zonedata(self):
        def raise_transfererror(zone_name=None,
                                zone_file=None,
                                host=None,
                                port=None,
                                key_id=None,
                                key_data=None,
                                key_algo=None):
            if zone_name == 'test1.zone.pl' and \
                    zone_file == '/tmp/example.com.zone':
                # We are not testing this here:
                pass
            elif host in ['master1', 'master2']:
                # These we want out:
                raise check_zonesync.ZoneTransferFailed()
            else:
                pass
        self.mocks["check_zonesync.fetch_domain_data"].side_effect = \
            raise_transfererror

        with self.assertRaises(SystemExit):
            check_zonesync.main(paths.TEST_NOZONEFILE_CONFIG_FILE)

        self.assertFalse(
            self.mocks["check_zonesync.ScriptStatus"].notify_immediate.called)
        self.mocks["check_zonesync.ScriptStatus"].notify_agregated.assert_called_once_with()
        all_updates_were_critical = all([x[0][0] == 'critical' for x in
             self.mocks["check_zonesync.ScriptStatus"].update.call_args_list])
        self.assertTrue(
            all_updates_were_critical and
            len(self.mocks["check_zonesync.ScriptStatus"].update.call_args_list) > 0)

    def test_soa_records_differ(self):
        self.zonediff_ret.record_types = set(['SOA', ])
        self.zonediff_ret.full = ['foo', 'bar', ]

        with self.assertRaises(SystemExit):
            check_zonesync.main(paths.TEST_CONFIG_FILE)

        self.assertFalse(self.mocks["check_zonesync.ScriptStatus"].notify_immediate.called)
        self.mocks["check_zonesync.ScriptStatus"].notify_agregated.assert_called_once_with()
        all_updates_were_critical = all([x[0][0] == 'warn'
            for x in self.mocks["check_zonesync.ScriptStatus"].update.call_args_list])
        self.assertTrue(all_updates_were_critical and
            len(self.mocks["check_zonesync.ScriptStatus"].update.call_args_list) > 0)

    def test_records_differ(self):
        self.zonediff_ret.record_types = set(['SOA', 'A'])
        self.zonediff_ret.full = ['foo', 'bar', ]

        with self.assertRaises(SystemExit):
            check_zonesync.main(paths.TEST_CONFIG_FILE)

        self.assertFalse(self.mocks["check_zonesync.ScriptStatus"].notify_immediate.called)
        self.mocks["check_zonesync.ScriptStatus"].notify_agregated.assert_called_once_with()
        all_updates_were_critical = all([x[0][0] == 'critical'
            for x in self.mocks["check_zonesync.ScriptStatus"].update.call_args_list])
        self.assertTrue(all_updates_were_critical and
            len(self.mocks["check_zonesync.ScriptStatus"].update.call_args_list) > 0)

if __name__ == '__main__':
    unittest.main()
