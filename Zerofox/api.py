#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
import requests
import json
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
        self.username = config['username']
        self.password = config['password']
        self.proxies = config['proxies']
        self.verify = config['verify']
        # self.session = requests.Session()

    def response(self, status, content):
        """
        status: success/failure
        content: JSON
        return: JSON
        """

        return {'status':status, 'content': content}

    def getApiKey(self):

        """
            Get API key from ZeroFOX with username and password. give Authorization token in future
            requests by setting config['key']
        """
        req = self.url + "/api-token-auth/"
        data = {'username': self.username,
                'password': self.password}
        try:
            resp =  requests.post(req, data=data, proxies=self.proxies, verify=self.verify)
            if resp.status_code == '200':
                return self.response("success", resp.json())
            else:
                return self.response("failure", resp.json())
        except requests.exceptions.RequestException as e:
            sys.exit("Error: {}".format(e))

    def getOpenAlerts(self, duration):

        """
            Get all open alerts sorted by severity, descending
        :duration : number of hours
        :return : alerts : dict
        """

        min_timestamp = (datetime.datetime.utcnow() - datetime.timedelta(minutes=duration)).isoformat()
        param = {
            "status": "open",
            "sort_field": "severity",
            "sort_direction": "desc",
            "min_timestamp": min_timestamp}
        req = self.url + "/alerts/"

        try:
            return self.session.get(req, headers={'Authorization': 'token {}'.format(self.key)},
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

    # def get_image(self, url):
    #     """
    #
    #     :param url:
    #     :return: response
    #     """
        # try:
        #     return requests.get(url, proxies=self.proxies,
        #                             verify=self.verify)
        # except requests.exceptions.RequestException as e:
        #     sys.exit("Error: {}".format(e))