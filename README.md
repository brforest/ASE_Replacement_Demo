# ASE_Replacement_Demo

## Existing APIs:

### API Query:
```
https://ase.arubanetworks.com/api/tags
```
### API Response:
```

```

### API Query: 
```
https://ase.arubanetworks.com/api/solutions/?page_size=1000&page=1&ordering=-modified&is_enabled=True&products=19&tags=257&restrict_read_access=None
```
### API Response:
```

```

### API Query:
```
https://ase.arubanetworks.com/api/solutions/260
```
### API Response:
```
{
    "id": 284,
    "title": "network_health_monitor.1.4",
    "description": "This script monitors the forwarding state of the set of LAGs specified by the customer and the link state of each interface regardless of LAG.",
    "hitcountPK": 285,
    "contributors": [
        5707,
        "..."
    ],
    "contributors_details": [
        {
            "id": 5707,
            "handle": "amit.borude",
            "date_joined": "2016-02-20T00:32:46.768797Z",
            "last_login": "2022-07-25T21:45:11.036217Z",
            "is_internal": true,
            "timezone_offset": 420,
            "solution_contributions_count": 81,
            "submitted_ideas_count": 0,
            "_meta": {
                "descriptor": "return obj.handle;",
                "name": "User",
                "name_plural": "Users"
            }
        },
        "..."
    ],
    "description_long": "<h4>Summary</h4>\n\n<p>This script monitors the forwarding state of the set of LAGs specified by the customer and the link state of each interface regardless of LAG.</p>\n\n<h4>(Minimum/Maximum) Software Version(s) Required (optional)</h4>\n\n<p>ArubaOS-CX 10.05 Recommended Minimum</p>\n\n<h4>script Description</h4>\n\n<p>The main components of the script are Manifest, Parameter Definitions and the Python code.&nbsp;&nbsp;</p>\n\n<ul>\n\t<li>&#39;Manifest&#39; defines the unique name for this script.</li>\n</ul>\n\n<ul>\n\t<li>&#39;Parameter Definitions&#39; defines the input parameters to the script. This script requires the following parameters:&nbsp;</li>\n</ul>\n\n<ol>\n\t<li>lag_name_1 &ndash; This parameter specifies lag name. Default value is &#39; &#39;.</li>\n\t<li>lag_name_2&nbsp;-&nbsp;This parameter specifies lag name. Default value is &#39; &#39;.</li>\n\t<li>lag_name_3&nbsp;-&nbsp;This parameter specifies lag name. Default value is &#39; &#39;.</li>\n\t<li>lag_name_4&nbsp;-&nbsp;This parameter specifies lag name. Default value is &#39; &#39;.</li>\n\t<li>lag_name_5 -&nbsp;This parameter specifies lag name. Default value is &#39; &#39;.</li>\n\t<li>lag_name_6 -&nbsp;This parameter specifies lag name. Default value is &#39; &#39;.</li>\n\t<li>lag_name_7 -&nbsp;This parameter specifies lag name. Default value is &#39; &#39;.</li>\n\t<li>lag_name_8 -&nbsp;This parameter specifies lag name. Default value is &#39; &#39;.&nbsp;</li>\n</ol>\n\n<p>The script defines Monitor(s), Condition(s) and Action(s) :&nbsp;</p>\n\n<ul>\n\t<li><strong>Monitors</strong>:&nbsp; &nbsp;\n\n\t<ol>\n\t\t<li>forwarding_state - Port&#39;s forwarding state which is determined by state of the interface(s) of LAG:\n\t\t<ul>\n\t\t\t<li>forwarding - Summarizes the state of all the contributors that can block the Port.</li>\n\t\t\t<li>blocking_layer - Name of the layer that is blocking the forwarding_state.</li>\n\t\t</ul>\n\t\t</li>\n\t</ol>\n\t</li>\n\t<li>\n\t<p><strong>Conditions</strong>:&nbsp;</p>\n\n\t<ol>\n\t\t<li>\n\t\t<p>Conditions are defined to verify the transition of forwarding state of configured LAG from &quot;true&quot; to &quot;false&quot; AND blocking layer from any state to &quot;AGGREGATION&quot; .&nbsp;&nbsp;</p>\n\t\t</li>\n\t</ol>\n\t</li>\n\t<li>\n\t<p><strong>Actions</strong>:&nbsp;&nbsp;</p>\n\n\t<ol>\n\t\t<li>\n\t\t<p>Critical alert &ndash;&nbsp;When the monitoring condition is met, agent status is changed to Critical. Output of CLI command (&#39;show&nbsp;lacp&nbsp;aggregate {lag_id}&#39;) is displayed &nbsp;in the monitoring agent UI.&nbsp;</p>\n\t\t</li>\n\t\t<li>\n\t\t<p>Normal alert -&nbsp;&nbsp;When blocking layer and forwarding state is transitioned back to &quot;NONE&quot; and &quot;true&quot; respectively, then the agent status is set back to &#39;Normal&#39;.&nbsp;</p>\n\t\t</li>\n\t</ol>\n\t</li>\n</ul>\n\n<p>&nbsp;</p>\n\n<p>Condition is defined to monitor &#39;link_state&#39; of all interfaces. &#39;link_state&#39; specifies the Link&#39;s carrier status of an interface. If the link state of an interface transitions from &quot;up&quot; to &quot;down&quot; then the following actions are taken:</p>\n\n<ul>\n\t<li>Agent status is set to Critical.</li>\n\t<li>CLI commands executed to capture lldp configuration and extended information of the interface which has gone down.</li>\n</ul>\n\n<p>If the link state of all enabled interfaces comes back to the &quot;up&quot; state then the agent status is set back to Normal.</p>\n\n<p>In this script overall status of agent depends on state of each of the sub script.</p>\n\n<p>This monitored data is then plotted in a time-series chart for analysis purpose.</p>\n\n<h4>Platform(s) Tested</h4>\n\n<p>8400, 8360, 8325, 8320, 6400, 6300, 6200, 10000</p>\n\n<h4>Licenses</h4>\n\n<p>Apache License, Version 2.0</p>\n\n<h4>References</h4>\n\n<ul>\n\t<li><a href=\"http://https://www.arubanetworks.com/resource/network-analytics-engine-solution-overview/\">https://www.arubanetworks.com/resource/network-analytics-engine-solution-overview/</a></li>\n</ul>",
    "instructions_to_apply": "<h4>Applying the Generated Configuration</h4>\n\n<p>Use the Switch Web UI Network Analytics Engine Page, upload this script and instantiate an agent.</p>\n\n<h4>Verification</h4>\n\n<p>Ensure that as part of successful configuration, administrator is able to instantiate agents without any errors and is able to view monitored values plotted as data points on time series charts for analysis purpose in the WEB-UI.</p>\n\n<h4>Troubleshooting (Optional)</h4>\n\n<p><span style=\"font-family: inherit;\">N/A</span></p>\n\n<p><span style=\"color: rgb(245, 130, 31); font-family: inherit; font-size: 15px; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase;\">Frequently Asked Questions (FAQ) &nbsp;(Optional)</span></p>\n\n<p>N/A</p>",
    "_config_text_safe": "(#begindevice name=\"network_health_monitor.1.4\" type=\"py\" #)\n# -*- coding: utf-8 -*-\n#\n# (c) Copyright 2019-2021 Hewlett Packard Enterprise Development LP\n#\n# Licensed under the Apache License, Version 2.0 (the \"License\");\n# you may not use this file except in compliance with the License.\n# You may obtain a copy of the License at\n#\n# http://www.apache.org/licenses/LICENSE-2.0\n#\n# Unless required by applicable law or agreed to in writing,\n# software distributed under the License is distributed on an\n# \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY\n# KIND, either express or implied. See the License for the\n# specific language governing permissions and limitations\n# under the License.\n\nimport uuid\nimport ast\nimport requests\nfrom urllib.parse import unquote\nimport json\n\nManifest = {\n    'Name': 'network_health_monitor',\n    'Description': 'This script monitors the forwarding state of the set '\n                   'of LAGs specified by the customer and the link state '\n                   'of each interface regardless of LAG.',\n    'Version': '1.4',\n    'TargetSoftwareVersion': '10.05',\n    'Tags': ['bridging'],\n    'Author': 'HPE Aruba Networking'\n}\n\nParameterDefinitions = {\n    'lag_name_1': {\n        'Name': 'Name of the LAG to be monitored',\n        'Description': 'Name of the LAG for which status is to be monitored',\n        'Type': 'string',\n        'Default': ''\n    },\n    'lag_name_2': {\n        'Name': 'Name of the LAG to be monitored',\n        'Description': 'Name of the LAG for which status is to be monitored',\n        'Type': 'string',\n        'Default': ''\n    },\n    'lag_name_3': {\n        'Name': 'Name of the LAG to be monitored',\n        'Description': 'Name of the LAG for which status is to be monitored',\n        'Type': 'string',\n        'Default': ''\n    },\n    'lag_name_4': {\n        'Name': 'Name of the LAG to be monitored',\n        'Description': 'Name of the LAG for which status is to be monitored',\n        'Type': 'string',\n        'Default': ''\n    },\n    'lag_name_5': {\n        'Name': 'Name of the LAG to be monitored',\n        'Description': 'Name of the LAG for which status is to be monitored',\n        'Type': 'string',\n        'Default': ''\n    },\n    'lag_name_6': {\n        'Name': 'Name of the LAG to be monitored',\n        'Description': 'Name of the LAG for which status is to be monitored',\n        'Type': 'string',\n        'Default': ''\n    },\n    'lag_name_7': {\n        'Name': 'Name of the LAG to be monitored',\n        'Description': 'Name of the LAG for which status is to be monitored',\n        'Type': 'string',\n        'Default': ''\n    },\n    'lag_name_8': {\n        'Name': 'Name of the LAG to be monitored',\n        'Description': 'Name of the LAG for which status is to be monitored',\n        'Type': 'string',\n        'Default': ''\n    }\n}\n\n\nclass LinkState:\n\n    def __init__(self, agent, alm):\n        self.name = self.__class__.__name__\n        self.agent = agent\n        self.alm = alm\n        self.monitors = {}\n        self.rules = {}\n        self.graphs = {}\n\n    def create_monitors(self):\n        # monitor link state\n        uri = '/rest/v1/system/interfaces/*?attributes=link_state' \\\n              '&filter=type:system'\n        self.monitors['link_state'] = \\\n            Monitor(uri, 'Interface Link status')\n        return list(self.monitors.values())\n\n    def create_rules(self):\n        # ----------------------------------------\n        # Rule tracking link state\n        # ----------------------------------------\n        rule = Rule('Link State')\n\n        # set condition when link goes down\n        rule.condition(\n            'transition {} from \"up\" to \"down\"',\n            [self.monitors['link_state']])\n        rule.action(self.action_interface_down)\n\n        # clear condition when link goes up\n        rule.clear_condition(\n            'transition {} from \"down\" to \"up\"',\n            [self.monitors['link_state']])\n        rule.clear_action(self.action_interface_up)\n\n        # store rule\n        self.rules['link_state'] = rule\n\n        return list(self.rules.values())\n\n    def create_graphs(self):\n        if bool(self.monitors):\n            self.graphs['link_state'] = \\\n                Graph(list(self.monitors.values()),\n                      title=Title(\"Link State Monitor\"),\n                      dashboard_display=True)\n            return list(self.graphs.values())\n        else:\n            return []\n\n    def parse_interface_event(self, event):\n        self.agent.logger.debug('XC parse {}'.format(event))\n        interface_id = event['labels'].split(',')[0]\n        interface_id = interface_id.split('=')[1]\n        return event['rule_description'], interface_id\n\n    def action_interface_down(self, event):\n        rule_desc, interface_id = self.parse_interface_event(event)\n        links_down = json.loads(self.agent.variables['links_down'])\n\n        # log\n        self.agent.logger.debug('XC ================ Down ================')\n        self.agent.logger.debug('XC label: {}'.format(event['labels']))\n        self.agent.logger.debug('XC interface_id: {}'.format(interface_id))\n        self.agent.logger.debug('XC links_down before: {}'.format(links_down))\n\n        # check history\n        if interface_id not in links_down:\n\n            # add interface to tracking\n            links_down.append(interface_id)\n            # update data store\n            self.agent.variables['links_down'] = json.dumps(links_down)\n            # log\n            self.agent.action_cli(\n                'show lldp configuration {}'.format(interface_id))\n            self.agent.action_cli(\n                'show interface {} extended'.format(interface_id))\n            # alert\n            self.alm.publish_alert_level(\n                self.name, rule_desc, AlertLevel.MINOR)\n\n        # log\n        self.agent.logger.debug('XC links_down after: {}'.format(links_down))\n        self.agent.logger.debug('XC ================ /Down ================')\n\n    def action_interface_up(self, event):\n        rule_desc, interface_id = self.parse_interface_event(event)\n        links_down = json.loads(self.agent.variables['links_down'])\n\n        # log\n        self.agent.logger.debug('XC ================ Up ================')\n        self.agent.logger.debug('XC label: {}'.format(event['labels']))\n        self.agent.logger.debug('XC interface_id: {}'.format(interface_id))\n        self.agent.logger.debug('XC links_down before: {}'.format(links_down))\n\n        # check history\n        if interface_id in links_down:\n            # remove interface from tracking\n            links_down.pop(links_down.index(interface_id))\n            # update data store\n            self.agent.variables['links_down'] = json.dumps(links_down)\n            # alert\n            if not links_down:\n                self.alm.publish_alert_level(\n                    self.name, rule_desc, AlertLevel.NONE)\n\n        # log\n        self.agent.logger.debug('XC links_down after: {}'.format(links_down))\n        self.agent.logger.debug('XC ================ /Up ================')\n\n\nclass LagHealth:\n\n    def __init__(self, agent, alm):\n        self.name = self.__class__.__name__\n        self.agent = agent\n        self.alm = alm\n        self.monitors = {}\n        self.rules = {}\n        self.graphs = {}\n\n    def create_monitors(self):\n        known_lags = json.loads(self.agent.variables['known_lags'])\n        for lag_id, lag_name in known_lags:\n            lag_value = self.agent.params[lag_name].value\n            lag_monitor = 'lag_forwarding_monitor_' + lag_id\n            port_monitor = 'port_blocking_monitor_' + lag_id\n\n            # monitor LAG forwarding state\n            uri = '/rest/v1/system/ports/{}?' \\\n                  'attributes=forwarding_state.forwarding'\n            self.monitors[lag_monitor] = \\\n                Monitor(uri, 'Forwarding State ' + lag_value,\n                        [self.agent.params[lag_name]])\n\n            # monitor LAG blocking layer\n            uri = '/rest/v1/system/ports/{}?' \\\n                  'attributes=forwarding_state.blocking_layer'\n            self.monitors[port_monitor] = \\\n                Monitor(uri, 'Port Blocking Layer ' + lag_value,\n                        [self.agent.params[lag_name]])\n\n        return list(self.monitors.values())\n\n    def create_rules(self):\n        known_lags = json.loads(self.agent.variables['known_lags'])\n        # list of tuples\n        for lag_id, _ in known_lags:\n            lag_transition_false = 'lag_transition_false' + lag_id\n            aggregation_blocked = 'aggregation_blocked' + lag_id\n\n            lag_monitor = 'lag_forwarding_monitor_' + lag_id\n            port_monitor = 'port_blocking_monitor_' + lag_id\n\n            # ----------------------------------------\n            # Rule tracking LAG forwarding state\n            # ----------------------------------------\n            rule = Rule('Port Forwarding is false')\n\n            # set condition when exiting forwarding state\n            rule.condition(\n                'transition {} from \"true\" to \"false\"',\n                [self.monitors[lag_monitor]])\n            rule.action(self.status_transition_action)\n\n            # clear condition when entering forwarding state\n            rule.clear_condition(\n                'transition {} from \"false\" to \"true\"',\n                [self.monitors[lag_monitor]])\n            rule.clear_action(self.status_transition_action)\n\n            # store rule\n            self.rules[lag_transition_false] = rule\n\n            # ----------------------------------------\n            # Rule tracking LAG blocking layer\n            # ----------------------------------------\n            rule = Rule('Forwarding state is blocked by AGGREGATION layer')\n\n            # set condition when entering blocking state\n            rule.condition(\n                '{} == \"AGGREGATION\"',\n                [self.monitors[port_monitor]])\n            rule.action(self.blocking_layer_action)\n\n            # clear condition when exiting blocking state\n            rule.clear_condition(\n                '{} != \"AGGREGATION\"',\n                [self.monitors[port_monitor]])\n            rule.clear_action(self.blocking_layer_normal)\n\n            # store rule\n            self.rules[aggregation_blocked] = rule\n\n        return list(self.rules.values())\n\n    def create_graphs(self):\n        if bool(self.monitors):\n            self.graphs['lag_health'] = \\\n                Graph(list(self.monitors.values()),\n                      title=Title(\"Lag Health Monitor\"),\n                      dashboard_display=False)\n            return list(self.graphs.values())\n        else:\n            return []\n\n    def parse_lag_event(self, event):\n        self.agent.logger.debug('XC parse {}'.format(event))\n        lag_id = event['labels'].split(',')[0]\n        lag_id = lag_id.split('=')[1]\n        return event['rule_description'], lag_id\n\n    def status_transition_action(self, event):\n        rule_desc, lag_id = self.parse_lag_event(event)\n        # event value is in JSON format\n        event_data = event['value']\n        # log\n        self.agent.logger.info('Forwarding: {}'.format(event_data))\n        # update data store\n        self.agent.variables['forwarding'] = event_data\n        # report\n        self.report_alert_status(lag_id, rule_desc)\n\n    def blocking_layer_action(self, event):\n        rule_desc, lag_id = self.parse_lag_event(event)\n        event_data = json.dumps(True)\n        # log\n        self.agent.logger.info('Blocking layer: {}'.format(event_data))\n        # update data store\n        self.agent.variables['blocked_by_aggregation'] = event_data\n        # report\n        self.report_alert_status(lag_id, rule_desc)\n\n    def blocking_layer_normal(self, event):\n        rule_desc, lag_id = self.parse_lag_event(event)\n        event_data = json.dumps(False)\n        # log\n        self.agent.logger.info('Blocking layer: {}'.format(event_data))\n        # update data store\n        self.agent.variables['blocked_by_aggregation'] = event_data\n        # report\n        self.report_alert_status(lag_id, rule_desc)\n\n    def report_alert_status(self, lag_id, rule_desc):\n        critical_lags = json.loads(self.agent.variables['critical_lags'])\n        self.agent.logger.debug('XC critical lags before: {}'\n                                .format(critical_lags))\n\n        if (not json.loads(self.agent.variables['forwarding']) and\n                json.loads(self.agent.variables['blocked_by_aggregation'])):\n            if lag_id not in critical_lags:\n                # add LAG to tracking\n                critical_lags.append(lag_id)\n                # update data store\n                self.agent.variables['critical_lags'] = json.dumps(\n                    critical_lags)\n                # log\n                self.agent.action_cli('show lacp aggregates {}'.format(lag_id))\n                self.agent.action_cli('show lacp interfaces')\n                # alert\n                self.alm.publish_alert_level(\n                    self.name, rule_desc, AlertLevel.CRITICAL)\n\n        elif lag_id in critical_lags:\n            # remove LAG from tracking\n            critical_lags.pop(critical_lags.index(lag_id))\n            # update data store\n            self.agent.variables['critical_lags'] = json.dumps(critical_lags)\n            # log\n            self.agent.logger.debug(\n                'XC Unset the previous status for {}'.format(lag_id))\n            # alert\n            if not critical_lags:\n                self.alm.publish_alert_level(\n                    self.name, rule_desc, AlertLevel.NONE)\n\n        self.agent.logger.debug(\n            'XC critical lags after: {}'.format(critical_lags))\n\n\nclass AlertManager:\n    def __init__(self, agent):\n        self.agent = agent\n\n    def publish_alert_level(self, metric_desc, rule_desc, level):\n        self.agent.logger.debug('XC rule_desc: {}'.format(rule_desc))\n        self.agent.logger.debug(\n            'XC metric={}, level={}'.format(metric_desc, level))\n        if 'metrics' not in self.agent.variables.keys():\n            # create dictionary\n            metrics = {}\n        else:\n            # load dictionary\n            metrics = dict(ast.literal_eval(self.agent.variables['metrics']))\n\n        if metric_desc not in metrics.keys():\n            agent_alert_level = AlertLevel.NONE  # initial severity\n        else:\n            agent_alert_level = level  # follow up severity\n\n        # update dictionary\n        metrics[metric_desc] = level\n        # store dictionary\n        self.agent.variables['metrics'] = str(metrics)\n        # log\n        self.agent.logger.debug('XC metrics={}'.format(metrics))\n\n        # escalate alert level based on prior events\n        for severity in metrics.values():\n            if severity == AlertLevel.CRITICAL:\n                agent_alert_level = AlertLevel.CRITICAL\n            elif severity == AlertLevel.MAJOR:\n                if agent_alert_level != AlertLevel.CRITICAL:\n                    agent_alert_level = AlertLevel.MAJOR\n            elif severity == AlertLevel.MINOR:\n                if (agent_alert_level != AlertLevel.CRITICAL and\n                        agent_alert_level != AlertLevel.MAJOR):\n                    agent_alert_level = AlertLevel.MINOR\n\n        # update agent alert level\n        if agent_alert_level != AlertLevel.NONE:\n            # set agent alert\n            self.agent.logger.debug('XC setting {} alert level'\n                                    .format(agent_alert_level))\n            self.agent.set_alert_level(agent_alert_level)\n        else:\n            # remove agent alert\n            self.agent.logger.debug('XC removing alert level')\n            self.agent.remove_alert_level()\n\n\nclass Agent(NAE):\n    def __init__(self):\n        alm = AlertManager(self)\n\n        # classes\n        self.link_state = LinkState(self, alm)\n        self.lag_health = LagHealth(self, alm)\n\n        # tracking\n        self.variables['links_down'] = json.dumps([])\n        self.variables['known_lags'] = json.dumps([])\n        self.variables['critical_lags'] = json.dumps([])\n\n        # database variable 'forwarding_state.forwarding'\n        self.variables['forwarding'] = json.dumps(True)\n\n        # database variable 'forwarding_state.blocking_layer'\n        self.variables['blocked_by_aggregation'] = json.dumps(False)\n\n        # build list of known LAGs\n        self.build_known_lags()\n\n        # merge objects\n        self.__merge(self.link_state)\n        self.__merge(self.lag_health)\n\n    def build_known_lags(self):\n        known_lags = []\n        for i in range(1, 9):\n            lag_id = str(i)\n            lag_name = 'lag_name_' + lag_id\n            if self.params[lag_name].value:\n                known_lags.append((lag_id, lag_name))\n\n        # update data store\n        self.variables['known_lags'] = json.dumps(sorted(known_lags))\n\n    def __merge(self, script):\n        self.__merge_monitors(script.create_monitors())\n        self.__merge_rules(script.create_rules())\n        self.__merge_graphs(script.create_graphs())\n\n    def __merge_monitors(self, monitors):\n        for i, _ in enumerate(monitors):\n            monitor_id = uuid.uuid4().hex\n            mon = 'monitor_{}'.format(monitor_id)\n            setattr(self, mon, monitors[i])\n        return monitors\n\n    def __merge_rules(self, rules):\n        for i, _ in enumerate(rules):\n            monitor_id = uuid.uuid4().hex\n            rule = 'rule_{}'.format(monitor_id)\n            setattr(self, rule, rules[i])\n        return rules\n\n    def __merge_graphs(self, graphs):\n        for i, _ in enumerate(graphs):\n            monitor_id = uuid.uuid4().hex\n            graph = 'graph_{}'.format(monitor_id)\n            setattr(self, graph, graphs[i])\n        return graphs\n\n    # Classwise wrapper methods to trigger callback actions\n    def action_syslog(self, metric_args):\n        ActionSyslog(metric_args, severity=SYSLOG_WARNING)\n\n    def action_cli(self, metric_args):\n        ActionCLI(metric_args)\n\n    def action_interface_down(self, event):\n        self.link_state.action_interface_down(event)\n\n    def action_interface_up(self, event):\n        self.link_state.action_interface_up(event)\n\n    def status_transition_action(self, event):\n        self.lag_health.status_transition_action(event)\n\n    def blocking_layer_action(self, event):\n        self.lag_health.blocking_layer_action(event)\n\n    def blocking_layer_normal(self, event):\n        self.lag_health.blocking_layer_normal(event)\n\n(#enddevice#)",
    "_config_undo_text_safe": "",
    "internal_notes_safe": "",
    "fields": [],
    "fields_details": [],
    "created": "2021-01-13T02:14:25.855291Z",
    "modified": "2024-06-06T19:15:53.759896Z",
    "created_by": {
        "id": 23991,
        "handle": "martin.harris",
        "date_joined": "2020-07-14T23:38:10.646106Z",
        "last_login": "2023-02-06T16:12:49.846581Z",
        "is_internal": true,
        "timezone_offset": -120,
        "solution_contributions_count": 12,
        "submitted_ideas_count": 0,
        "_meta": {
            "descriptor": "return obj.handle;",
            "name": "User",
            "name_plural": "Users"
        }
    },
    "modified_by": {
        "id": 32163,
        "handle": "beau.forest",
        "date_joined": "2024-01-30T22:06:35.593053Z",
        "last_login": "2024-07-02T17:33:12.742781Z",
        "is_internal": true,
        "timezone_offset": 420,
        "solution_contributions_count": 56,
        "submitted_ideas_count": 0,
        "_meta": {
            "descriptor": "return obj.handle;",
            "name": "User",
            "name_plural": "Users"
        }
    },
    "products": [
        19
    ],
    "products_details": [
        {
            "id": 19,
            "name": "NAE",
            "acronym": "NAE",
            "version_regex": "",
            "human_readable_version_regex": "",
            "_meta": {
                "descriptor": "return obj.acronym + \": \" + obj.name;",
                "name": "Product",
                "name_plural": "Products"
            },
            "solutions": [
                192,
                "..."
            ]
        }
    ],
    "hooks_details": [],
    "cached": {
        "groups": []
    },
    "tags": [
        184,
        "..."
    ],
    "tags_details": [
        {
            "id": 184,
            "name": "8400x",
            "_meta": {
                "descriptor": "return obj.name;",
                "name": "Tag",
                "name_plural": "Tags"
            },
            "solutions": [
                183,
                "..."
            ]
        },
        "..."
    ],
    "views": 449,
    "vote_score": 0,
    "user_voted_up": false,
    "user_voted_down": false,
    "vote_model": "es_config_app.SolutionVote",
    "is_enabled": true,
    "allow_in_featured": true,
    "config_imgs": [],
    "config_imgs_details": [],
    "restrict_read_access": false,
    "restrict_read_domains": [],
    "restrict_read_emails": [],
    "restrict_write_access": true,
    "restrict_write_domains": [],
    "restrict_write_emails": [],
    "has_read_access": true,
    "has_write_access": false,
    "following_solution": false,
    "history": [
        {
            "id": 5061,
            "solution": {
                "description": "This script monitors overall network health of device",
                "products_details": [
                    {
                        "_meta": {
                            "name": "Product",
                            "name_plural": "Products"
                        },
                        "human_readable_version_regex": "",
                        "acronym": "NAE",
                        "version_regex": "",
                        "solutions": [
                            180,
                            "..."
                        ],
                        "id": 19,
                        "name": "NAE"
                    }
                ],
                "tags_details": [
                    {
                        "solutions": [
                            183,
                            "..."
                        ],
                        "id": 184,
                        "name": "8400x",
                        "_meta": {
                            "name": "Tag",
                            "name_plural": "Tags"
                        }
                    },
                    "..."
                ],
                "id": "",
                "title": "network_health_monitor.1.4"
            },
            "approval_status": "created",
            "change_message": "Initial Creation",
            "last_approval_message": "",
            "approval_history": {
                "history": [
                    {
                        "approval_message": "",
                        "prev_approval_status": "draft",
                        "approval_status": "pending",
                        "created_by": {
                            "is_internal": true,
                            "handle": "martin.harris",
                            "id": 23991
                        },
                        "timestamp": "2021-01-08 17:38:03.549793+00:00"
                    },
                    {
                        "approval_message": "",
                        "prev_approval_status": "pending",
                        "approval_status": "created",
                        "created_by": {
                            "is_internal": true,
                            "handle": "ctang",
                            "id": 445
                        },
                        "timestamp": "2021-01-13 02:14:26.892705+00:00"
                    }
                ]
            },
            "created": "2020-09-21T21:59:37.912502Z",
            "modified": "2021-01-13T02:14:26.902429Z",
            "created_by": {
                "id": 23991,
                "handle": "martin.harris",
                "date_joined": "2020-07-14T23:38:10.646106Z",
                "last_login": "2023-02-06T16:12:49.846581Z",
                "is_internal": true,
                "timezone_offset": -120,
                "solution_contributions_count": 12,
                "submitted_ideas_count": 0,
                "_meta": {
                    "descriptor": "return obj.handle;",
                    "name": "User",
                    "name_plural": "Users"
                }
            },
            "modified_by": {
                "id": 445,
                "handle": "ctang",
                "date_joined": "2013-09-26T01:38:41.975406Z",
                "last_login": "2024-07-04T05:59:34.623761Z",
                "is_internal": true,
                "timezone_offset": -60,
                "solution_contributions_count": 126,
                "submitted_ideas_count": 0,
                "_meta": {
                    "descriptor": "return obj.handle;",
                    "name": "User",
                    "name_plural": "Users"
                }
            },
            "target_obj": 284,
            "has_read_access": true,
            "has_write_access": true
        },
        "..."
    ]
}
```
