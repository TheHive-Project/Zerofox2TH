#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
import requests
import sys
import datetime


class ZerofoxApi():
    """
        Python API for ZeroFOX

        :param config
    """

    def __init__(self, config):
        self.url = config['url']
        self.key = config['key']
        self.proxies = config['proxies']
        self.verify = config['verify']
        self.username = config.get('username', None)
        self.password = config.get('password', None)

    def response(self, status, content):
        """
        status: success/failure
        content: dict
        return: dict
        """
        return {'status': status, 'data': content}

    def getApiKey(self):

        """
            Get API key from ZeroFOX with username and password. give
                Authorization token in future
            requests by setting config['key']
        """
        req = self.url + "/api-token-auth/"
        data = {'username': self.username,
                'password': self.password}
        try:
            resp = requests.post(req, data=data, proxies=self.proxies,
                                 verify=self.verify)
            if resp.status_code == 200:
                return self.response("success", resp.json())
            else:
                return self.response("failure", resp.json())
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))

    def find_alerts(self, last):

        """
        Get all open alerts sorted by severity, descending
        :last: number of minutes
        :return: alerts
        :rtype: dict
        """

        min_timestamp = (datetime.datetime.utcnow() -
                         datetime.timedelta(minutes=last)).isoformat()
        param = {
            "status": "open",
            "sort_field": "severity",
            "sort_direction": "desc",
            "min_timestamp": min_timestamp}
        req = self.url + "/alerts/"

        try:
            resp = requests.get(req, headers={'Authorization':
                                              'token {}'.format(self.key)},
                                params=param, proxies=self.proxies,
                                verify=self.verify)
            if resp.status_code == 200:
                return self.response("success", resp.json())
            else:
                return self.response("failure", resp.json())
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))

    def get_alerts(self, id):

        """
            Get Alert by Id
        :param id:
        :type id: int
        :return: response()
        :rtype: dict
        """
        req = self.url + "/alerts/{}/".format(id)

        try:
            resp = requests.get(req, headers={'Authorization':
                                              'token {}'.format(self.key)},
                                proxies=self.proxies,
                                verify=self.verify)
            if resp.status_code == 200:
                return self.response("success", resp.json())
            else:
                return self.response("failure", resp.json())
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))

    def get_image(self, url):
        """
        :param url:
        :type: string
        :return: response
        :rtype: requests.response
        """
        try:
            return requests.get(url, headers={'Authorization':
                                              'token {}'.format(self.key)},
                                proxies=self.proxies, verify=self.verify)
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))
