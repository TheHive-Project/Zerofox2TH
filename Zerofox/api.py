#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
import requests
import json
import sys

class ZeroFoxApi():


    """
        Python API for ZeroFOX

        :param config
    """

    def __init__(self, config):
        self.url = config['url']
        self.key = config['key']
        self.username=config['username']
        self.password=config['password']
        self.proxies = config['proxies']
        self.verify = config['verify']
        self.session = requests.Session()
        # self.auth= requests.auth.HTTPBasicAuth(username=self.api)

    def getApiKey(self):

        """
            Get API key from ZeroFOX with username and password. give Authorization token in future
            requests by setting config['key']
        """
        req = self.url + "/api-token-auth/"
        data = {'username': self.username,
                'password': self.password}
        try:
            return self.session.post(req, data=data, proxies=self.proxies, verify=self.verify)
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))


    def getOpenAlerts(self):

        """
            Get all open alerts sorted by severity, descending
        """

        param = {
            "status": "open",
            "sort_field": "severity",
            "sort_direction": "desc"}
        req = self.url + "/alerts/"

        try:
            return self.session.get(req, headers={'Authorization':'token {}'.format(self.key)},
                                    params=param, proxies=self.proxies, verify=self.verify)
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))


    def getAlertId(self, id):

        """
            Get Alert by Id
        """
        req = self.url + "/alerts/{}/".format(id)

        try:
            return self.session.get(req, headers={'Authorization': 'token {}'.format(self.key)}, proxies=self.proxies,
                                verify=self.verify)
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))
