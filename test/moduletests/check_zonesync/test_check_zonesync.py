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

# To perform local imports first we need to fix PYTHONPATH:
pwd = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.abspath(pwd + '/../../modules/'))

# Local imports:
import file_paths as paths
import check_zonesync


class TestCheckZoneSync(unittest.TestCase):

    def test_argument_parsing(self):
        ret = check_zonesync.parse_command_line(script_name="test-scriptname",
                                                args=["-c", "/path/to/test",
                                                      "--verbose"])

        self.assertEqual({'config_file': '/path/to/test',
                          'std_err': False,
                          'verbose': True},
                         ret)

        ret = check_zonesync.parse_command_line(script_name="other-scriptname",
                                                args=["-c", "/path/to/test", "-s"])

        self.assertEqual({'config_file': '/path/to/test',
                          'std_err': True,
                          'verbose': False},
                         ret)

        ret = check_zonesync.parse_command_line(script_name="other-scriptname",
                                                args=["-c", "/path/to/other/test"])

        self.assertEqual({'config_file': '/path/to/other/test',
                          'std_err': False,
                          'verbose': False},
                         ret)

    @mock.patch('dns.tsigkeyring.from_text')
    @mock.patch('dns.zone.from_xfr')
    @mock.patch('dns.query.xfr')
    def test_zone_data_fetch(self, DNSQueryXfrMock, DNSZoneFromXfrMock,
                             DNSKeyringFromTextMock):

        # Check if input argument sanity is checked:
        with self.assertRaises(pymisc.script.FatalException):
            check_zonesync.fetch_domain_data(zone_file="/path/to/zonefile",
                                             host="example.com")

        # Check file zone parsing:
        with self.assertRaises(check_zonesync.ZoneParseFailed):
            check_zonesync.fetch_domain_data(zone_file=paths.TEST_ZONE_BAD)

        check_zonesync.fetch_domain_data(zone_file=paths.TEST_ZONE_GOOD)

        # Check AXFR zone parsing:
        DNSKeyringFromTextMock.return_value = "test-keyring"
        DNSQueryXfrMock.return_value = "DNSQueryXfrMock teststring"
        DNSZoneFromXfrMock.return_value = "DNSZoneFromXfrMock teststring"

        # With a key:
        check_zonesync.fetch_domain_data(host="example-server.com",
                                         zone_name="example.com",
                                         port=53,
                                         key_id="example.com-key_id",
                                         key_data="1234567890",
                                         key_algo="sample-algo",
                                         )
        self.assertEqual(mock.call(zone='example.com',
                                   keyalgorithm='sample-algo',
                                   keyring='test-keyring',
                                   where='example-server.com',
                                   keyname='example.com-key_id',
                                   port=53),
                         DNSQueryXfrMock.call_args)
        DNSKeyringFromTextMock.reset_mock()
        DNSQueryXfrMock.reset_mock()
        DNSZoneFromXfrMock.reset_mock()

        # ... and without key:
        check_zonesync.fetch_domain_data(host="example-server.com",
                                         zone_name="example.com",
                                         port=53,
                                         )
        self.assertEqual(mock.call(zone='example.com',
                                   where='example-server.com',
                                   port=53,
                                   keyalgorithm=None,
                                   keyring=None,
                                   keyname=None,),
                         DNSQueryXfrMock.call_args)

    def test_zone_comparing(self):
        reference_zone = dns.zone.from_file(paths.TEST_ZONE_GOOD)

        # Both zones are the same:
        test_zone = dns.zone.from_file(paths.TEST_ZONE_GOOD)
        ret = check_zonesync.compare_domain_data(reference_zone, test_zone)
        self.assertEqual(ret.record_types, set([]))
        self.assertEqual(ret.full, [])

        # SOA differs:
        test_zone = dns.zone.from_file(paths.TEST_ZONE_GOOD_SOA_DIFFERS)
        ret = check_zonesync.compare_domain_data(reference_zone, test_zone)
        self.assertEqual(ret.record_types, set(["SOA"]))
        self.assertEqual(len(ret.full), 2)

        # Missing record:
        test_zone = dns.zone.from_file(paths.TEST_ZONE_GOOD_DELETED_RECORD)
        ret = check_zonesync.compare_domain_data(reference_zone, test_zone)
        self.assertEqual(ret.record_types, set(["CNAME"]))
        self.assertEqual(len(ret.full), 1)

        # Changed record:
        test_zone = dns.zone.from_file(paths.TEST_ZONE_GOOD_CHANGED_RECORD)
        ret = check_zonesync.compare_domain_data(reference_zone, test_zone)
        self.assertEqual(ret.record_types, set(["A"]))
        self.assertEqual(len(ret.full), 2)

        # Added record:
        test_zone = dns.zone.from_file(paths.TEST_ZONE_GOOD_ADDED_RECORD)
        ret = check_zonesync.compare_domain_data(reference_zone, test_zone)
        self.assertEqual(ret.record_types, set(['MX']))
        self.assertEqual(len(ret.full), 1)

    def test_host_data_verification(self):
        # Let's prepare correct data first:
        host_name = "example-host"
        zone = "example.com"
        good_hash = {"ip": "1.2.3.4",
                     "port": 53,
                     "key-id": "example-key",
                     "key-data": "1234567890abcdef",
                     "master": True,
                     }

        # Test if correct hash passes:
        msg = check_zonesync._verify_host_data(host_hash=good_hash,
                                               zone=zone,
                                               host_name=host_name)
        self.assertEqual(msg, [])

        # Test if bad IP fails:
        bad_hash = good_hash.copy()
        bad_hash["ip"] = "1000.1.2.3.4"
        msg = check_zonesync._verify_host_data(host_hash=bad_hash,
                                               zone=zone,
                                               host_name=host_name)
        self.assertEqual(len(msg), 1)

        # Test if missing IP fails:
        bad_hash = good_hash.copy()
        del bad_hash["ip"]
        msg = check_zonesync._verify_host_data(host_hash=bad_hash,
                                               zone=zone,
                                               host_name=host_name)
        self.assertEqual(len(msg), 1)

        # Test if malformed port fails:
        bad_hash = good_hash.copy()
        bad_hash["port"] = "53."
        msg = check_zonesync._verify_host_data(host_hash=bad_hash,
                                               zone=zone,
                                               host_name=host_name)
        self.assertEqual(len(msg), 1)

        # Test incompleate key set:
        bad_hash = good_hash.copy()
        del bad_hash["key-data"]
        msg = check_zonesync._verify_host_data(host_hash=bad_hash,
                                               zone=zone,
                                               host_name=host_name)
        self.assertEqual(len(msg), 1)

        # Test hostdata without keys:
        bad_hash = good_hash.copy()
        del bad_hash["key-id"]
        del bad_hash["key-data"]
        msg = check_zonesync._verify_host_data(host_hash=bad_hash,
                                               zone=zone,
                                               host_name=host_name)
        self.assertEqual(msg, [])

        # Test malformed key-id:
        bad_hash = good_hash.copy()
        bad_hash["key-id"] = 'this is not a proper key'
        msg = check_zonesync._verify_host_data(host_hash=bad_hash,
                                               zone=zone,
                                               host_name=host_name)
        self.assertEqual(len(msg), 1)

        # Test malformed key-data:
        bad_hash = good_hash.copy()
        bad_hash["key-data"] = 'aasfasdfdasf-asdfdas dasf'
        msg = check_zonesync._verify_host_data(host_hash=bad_hash,
                                               zone=zone,
                                               host_name=host_name)
        self.assertEqual(len(msg), 1)

    @mock.patch('os.path.exists')
    @mock.patch('os.access')
    @mock.patch('check_zonesync._verify_host_data')
    def test_configuration_verification(self, VerifyHostDataMock, OsAccessMock,
                                        OsPathExistsMock):
        # Load test configuration
        ScriptConfiguration.load_config(paths.TEST_CONFIG_FILE)
        conf_hash = ScriptConfiguration.get_config()

        # For now always OK:
        VerifyHostDataMock.return_value = []
        OsPathExistsMock.return_value = True
        OsAccessMock.return_value = True

        # Test proper configuration:
        msg = check_zonesync._verify_conf(conf_hash)
        self.assertEqual(msg, [])

        # Test malformed timeout:
        bad_conf = copy.deepcopy(conf_hash.copy())
        bad_conf['timeout'] = 'not an integer'
        msg = check_zonesync._verify_conf(bad_conf)
        self.assertEqual(len(msg), 1)

        # Test empty zone list:
        bad_conf = copy.deepcopy(conf_hash.copy())
        bad_conf['zones'] = {}
        msg = check_zonesync._verify_conf(bad_conf)
        self.assertEqual(len(msg), 1)

        # Test malformed zone name:
        bad_conf = copy.deepcopy(conf_hash.copy())
        bad_conf['zones']['a bad zone'] = bad_conf[
            'zones'].pop('test1.zone.pl')
        msg = check_zonesync._verify_conf(bad_conf)
        self.assertEqual(len(msg), 1)

        # Test zone without masters:
        bad_conf = copy.deepcopy(conf_hash.copy())
        del bad_conf['zones']['test1.zone.pl']['zonehosts']['master1']
        del bad_conf['zones']['test1.zone.pl']['zonehosts']['master2']
        msg = check_zonesync._verify_conf(bad_conf)
        self.assertEqual(len(msg), 1)

        # Test zone without datafile:
        bad_conf = copy.deepcopy(conf_hash.copy())
        del bad_conf['zones']['test1.zone.pl']['zonedata']
        del bad_conf['zones']['test1.zone.pl']['zonehosts']['master1']
        del bad_conf['zones']['test1.zone.pl']['zonehosts']['slavehost1']
        del bad_conf['zones']['test1.zone.pl']['zonehosts']['slavehost2']
        del bad_conf['zones']['test1.zone.pl']['zonehosts']['slavehost3']
        msg = check_zonesync._verify_conf(bad_conf)
        self.assertEqual(len(msg), 1)

        # Zone file does not exits:
        OsPathExistsMock.return_value = False
        msg = check_zonesync._verify_conf(conf_hash)
        self.assertEqual(len(msg), 1)

    @mock.patch('logging.warn')
    @mock.patch('logging.info')
    @mock.patch('logging.error')
    @mock.patch('check_zonesync.sys.exit')
    @mock.patch('check_zonesync.compare_domain_data')
    @mock.patch('check_zonesync.fetch_domain_data')
    @mock.patch('check_zonesync._verify_conf')
    @mock.patch('check_zonesync.ScriptLock')
    @mock.patch('check_zonesync.ScriptTimeout')
    @mock.patch('check_zonesync.ScriptStatus')
    def test_main_logic(self, ScriptStatusMock, ScriptTimeoutMock, ScriptLockMock,
                        VerifyConfMock, FetchDomainDataMock, CompareDomainData,
                        SysExitMock, *unused):

        # For now we give OK on everything:
        def terminate_script(exit_status):
            raise SystemExit(exit_status)
        SysExitMock.side_effect = terminate_script
        VerifyConfMock.return_value = []

        def terminate_script(*unused):
            raise SystemExit(216)
        ScriptStatusMock.notify_immediate.side_effect = terminate_script
        ScriptStatusMock.notify_agregated.side_effect = terminate_script

        # All OK:
        with self.assertRaises(SystemExit):
            check_zonesync.main(paths.TEST_CONFIG_FILE)
        self.assertFalse(ScriptStatusMock.notify_immediate.called)
        self.assertTrue(ScriptStatusMock.notify_agregated.called)
        ScriptStatusMock.notify_agregated.reset_mock()
        ScriptStatusMock.notify_immediate.reset_mock()

        # Configuration issues:
        VerifyConfMock.return_value = ["There is a problem with configuration"]
        with self.assertRaises(SystemExit):
            check_zonesync.main(paths.TEST_CONFIG_FILE)
        self.assertTrue(ScriptStatusMock.notify_immediate.called)
        self.assertEqual(ScriptStatusMock.notify_immediate.call_args[0][0],
                         'unknown')
        ScriptStatusMock.notify_immediate.reset_mock()
        VerifyConfMock.return_value = []

        # Problems parsing zone data:
        def raise_parserror(zone_name, zone_file, *unused_p, **unused_kw):
            if not unused_p and not unused_kw:
                raise check_zonesync.ZoneParseFailed
            else:
                # With this test data it should not happen
                self.fail("check_zonesync.fetch_domain_data called with non-file"
                          " arguments")
        FetchDomainDataMock.side_effect = raise_parserror
        with self.assertRaises(SystemExit):
            check_zonesync.main(paths.TEST_CONFIG_FILE)
        self.assertFalse(ScriptStatusMock.notify_immediate.called)
        self.assertTrue(ScriptStatusMock.notify_agregated.called)
        self.assertTrue(ScriptStatusMock.update.called)
        self.assertEqual(ScriptStatusMock.update.call_args[0][0], 'critical')
        ScriptStatusMock.notify_agregated.reset_mock()
        ScriptStatusMock.notify_immediate.reset_mock()
        ScriptStatusMock.update.reset_mock()

        # Problems with AXFR zone transfers:
        def raise_transfererror(zone_name, host, port, key_id, key_data,
                                key_algo, *unused_p, **unused_kw):
            if not unused_p and not unused_kw:
                raise check_zonesync.ZoneTransferFailed
            else:
                # With this test data it should not happen
                self.fail("check_zonesync.fetch_domain_data called with "
                          "non-zonetransfer arguments")
        FetchDomainDataMock.side_effect = raise_transfererror
        with self.assertRaises(SystemExit):
            import ipdb; ipdb.set_trace() # BREAKPOINT
            check_zonesync.main(paths.TEST_CONFIG_FILE)
        self.assertFalse(ScriptStatusMock.notify_immediate.called)
        self.assertTrue(ScriptStatusMock.notify_agregated.called)
        self.assertTrue(ScriptStatusMock.update.called)
        all_updates_were_critical = all([x[0][0] == critical for x in ScriptStatusMock.update.call_args])
        self.assertTrue(all_updates_were_critical)
        ScriptStatusMock.notify_agregated.reset_mock()
        ScriptStatusMock.notify_immediate.reset_mock()
        ScriptStatusMock.update.reset_mock()


if __name__ == '__main__':
    unittest.main()
