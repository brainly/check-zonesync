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
import mock
import os
import pymisc
import sys
import unittest
import dns

# To perform local imports first we need to fix PYTHONPATH:
pwd = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.abspath(pwd + '/../../modules/'))

# Local imports:
import file_paths as paths
import check_zonesync


class TestCheckZoneSync(unittest.TestCase):

    # Used by side effects:

    @staticmethod
    def _terminate_script(*unused):
        raise SystemExit(0)

    # Fake configuration data factory:
    def _script_conf_factory(self, **kwargs):
        good_configuration = {"lockfile": paths.TEST_LOCKFILE,
                              "history_file": paths.TEST_STATUSFILE,
                              }

        def func(key):
            config = good_configuration.copy()
            config.update(kwargs)
            self.assertIn(key, config)
            return config[key]

        return func

    def test_argument_parsing(self):
        ret = check_zonesync.parse_command_line(script_name="test-scriptname",
                                                args=["-c", "/path/to/test", "--verbose"])

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
        reference_zone =  dns.zone.from_file(paths.TEST_ZONE_GOOD)

        # Both zones are the same:
        test_zone =  dns.zone.from_file(paths.TEST_ZONE_GOOD)
        ret = check_zonesync.compare_domain_data(reference_zone,test_zone)
        self.assertEqual(ret.record_types, set([]))
        self.assertEqual(ret.full, [])

        # SOA differs:
        test_zone =  dns.zone.from_file(paths.TEST_ZONE_GOOD_SOA_DIFFERS)
        ret = check_zonesync.compare_domain_data(reference_zone,test_zone)
        self.assertEqual(ret.record_types, set(["SOA"]))
        self.assertEqual(len(ret.full), 2)

        # Missing record:
        test_zone =  dns.zone.from_file(paths.TEST_ZONE_GOOD_DELETED_RECORD)
        ret = check_zonesync.compare_domain_data(reference_zone,test_zone)
        self.assertEqual(ret.record_types, set(["CNAME"]))
        self.assertEqual(len(ret.full), 1)

        # Changed record:
        test_zone =  dns.zone.from_file(paths.TEST_ZONE_GOOD_CHANGED_RECORD)
        ret = check_zonesync.compare_domain_data(reference_zone,test_zone)
        self.assertEqual(ret.record_types, set(["A"]))
        self.assertEqual(len(ret.full), 2)

        # Added record:
        test_zone =  dns.zone.from_file(paths.TEST_ZONE_GOOD_ADDED_RECORD)
        ret = check_zonesync.compare_domain_data(reference_zone,test_zone)
        self.assertEqual(ret.record_types, set(['MX']))
        self.assertEqual(len(ret.full), 1)


if __name__ == '__main__':
    unittest.main()
