#-*- coding: utf-8 -*-
#
#(c) Copyright 2019-2020,2022-2023 Hewlett Packard Enterprise Development LP
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing,
#software distributed under the License is distributed on an
#"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#KIND, either express or implied.  See the License for the
#specific language governing permissions and limitations
#under the License.

import ast
import re
import requests
from collections import OrderedDict

Manifest = {
    'Name': 'arp_request_monitor',
    'Description': 'Monitoring number of ARP requests coming to the switch CPU',
    'Version': '1.1',
    'Author': 'HPE Aruba Networking',
    'AOSCXVersionMax': '10.11'
}

ParameterDefinitions = {
    'arp_request_count_threshold': {
        'Name': 'ARP Request Count (per minute)',
        'Description': 'This parameter represents a tolerance of number of ARP requests '
                       'coming to switch CPU in 1 minute. '
                       'The provided value is absolute sum of '
                       'Unicast and Broadcast ARP requests. ',
        'Type': 'Integer',
        'Default': 4000
    }
}

CoppClasses = {
    'arp_broadcast': 'routing',
    'arp_unicast': 'routing'
}

class Agent(NAE):
    """This agent monitors all ARP related classes in CoPP,
    setting up NAE Monitors for both traffic passed and dropped and uses periodic callback
        to calculate totals and set alerts,
    generating a analysis report with stats and configuration about ARP CoPP classes.

    The script is designed to work on ArubaOS-CX 10.01.XXXX and above versions.
    """

    URI_TEMPLATES = {
        'passed': '/rest/v1/system?attributes=copp_statistics.{}_{}_passed',
        'dropped': '/rest/v1/system?attributes=copp_statistics.{}_{}_dropped'
    }

    def __init__(self):
        unit = "packets"
        self.variables['unit'] = unit
        self.variables['arp_req_count'] = str(0)
        copp_classes = CoppClasses

        monitors = self.set_monitors(copp_classes, unit)
        self.set_rules(copp_classes, monitors)

    def set_monitors(self, copp_classes, unit):
        """Creates NAE Monitors for both traffic passed and dropped for each
        given CoPP Policy Class plus it creates monitors for total traffic
        passed and total traffic dropped.

        Since this function creates NAE Monitors based on a given list and the
        NAE Python Framework demands a NAE Monitor to be defined as class
        variables, this implementation has to use the `setattr` function to
        make sure all NAE Monitors work as expected.

        Keyword Arguments:
        copp_classes -- The list of CoPP Policy Classes
        unit -- The unit of traffic measurement: packets or bytes
        """

        monitors = {}
        for cc in copp_classes:
            passed_uri = Agent.URI_TEMPLATES['passed'].format(cc, unit)
            dropped_uri = Agent.URI_TEMPLATES['dropped'].format(cc, unit)

            monitors[cc] = {
                'passed': Monitor(Rate(passed_uri, '1 minute'), '{} traffic passed ({}/min)'.format(cc, unit)),
                'dropped': Monitor(Rate(dropped_uri, '1 minute'), '{} traffic dropped ({}/min)'.format(cc, unit))
            }

            var_name1 = 'monitor_{}_passed'.format(cc)
            setattr(self, var_name1, monitors[cc]['passed'])
            var_name2 = 'monitor_{}_dropped'.format(cc)
            setattr(self, var_name2, monitors[cc]['dropped'])
        return monitors

    def set_rules(self, copp_classes, monitors):
        rule = Rule('arp_count_callback')
        rule.condition('every 1 minute')
        rule.action(self.analyze_arps_total)

        var_name1 = 'rule_{}'.format("arp_broadcast")
        setattr(self, var_name1, rule)

    def analyze_arps_total(self, event):
        """Fires a NAE Alert if ARP count over the last minute exceeds threashold.

        """
        total = self.get_copp_policy_stats()
        delta = total - int(self.variables['arp_req_count'])
        self.variables['arp_req_count'] = str(total)
        threshold = int(self.params['arp_request_count_threshold'].value)

        if self.get_alert_level() != AlertLevel.CRITICAL and (delta > threshold):
            self.set_alert_level(AlertLevel.CRITICAL)
            message = "Number of ARP requests in the last minute " \
                "{} exceeded the threshold.".format(delta)
            self.logger.info(message)
            ActionSyslog(message, severity=SYSLOG_WARNING)

        elif self.get_alert_level() == AlertLevel.CRITICAL and (delta <= threshold):
            self.set_alert_level(AlertLevel.NONE)
            message = "Number of ARP requests in the last minute " \
                "{} dropped below the threshold.".format(delta)
            self.logger.info(message)
            ActionSyslog(message, severity=SYSLOG_WARNING)

    def get_copp_policy_stats(self):
        """Returns the total passed and dropped bytes of arp
        CoPP Policy Classes.
        """

        try:
            unit = self.variables['unit']
            uri = "/rest/v1/system?attributes=copp_statistics"
            r = requests.get(HTTP_ADDRESS + uri, verify=False,
                             proxies={'http': None, 'https': None})
            r.raise_for_status()
            copp_stats = r.json()
            passed_format = "{}_passed".format(unit)
            dropped_format = "{}_dropped".format(unit)
            total = 0
            for cc in CoppClasses:
                total += copp_stats['copp_statistics']["{}_{}".format(
                    cc, passed_format)]
                total += copp_stats['copp_statistics']["{}_{}".format(
                    cc, dropped_format)]
            return total

        except (requests.RequestException, requests.ConnectionError,
                requests.Timeout, requests.HTTPError, requests.URLRequired,
                requests.TooManyRedirects):
            self.error(
                'Failed to process HTTP request')
