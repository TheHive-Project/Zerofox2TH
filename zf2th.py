#!/usr/bin/env python3
# -*- coding: utf-8 -*-



from __future__ import print_function
from __future__ import unicode_literals

import sys
import getopt
import json
import getpass

from Zerofox.api import ZeroFoxApi
from config import Zerofox








def addTags(tags, **content):

    """
        add tag to tags

        :param tags is list
        :param content is text
    """
    for newtag in content:
        tags.appen("ZF:{}".format(newtag))
    return tags

def thsummary(comtent):

    """
        Build Case summary

        :param is dict
    """

def convertDs2ThCase(content):

    """
        convert Zerofox alert in a TheHive Case

        :content dict object
    """

    tasks = []
    tags = ["src:ZeroFOX"]
    tags = addTags(tags,
        content["alert"]["alert_type"],
        content["alert"]["entity"]["perpetrator"]["network"],
        content["alert"]["entity"]["name"],
        )

    if ('summary' in content) and (len(content['summary']) > 1):
        description = content.get('summary')
    else:
        description = content.get('description', {"-"})
    case = Case(
            title="[Zerofox] #{} ".format(content['id']) + content['title'],
            tlp=2,
            severity=thSeverity(content['severity']),
            flag=False,
            tags=tags,
            description = description)
    return case







def import2th(thapi, response):

    """
        Convert Zerofox response and import it in TheHive
        Call convertDs2ThCase
        Return the case fully created in TheHive

        :response  dict Response from Zerofox
    """

    case = convertDs2ThCase(response)
    thresponse = thapi.create_case(case)
    r = thresponse.json()
    caseAddTask(thapi, r['id'], response)



def run(argv):

"""
    Download Zerofox incident and create a new Case in TheHive

    :argv incident number
"""

    incidentId = ''

    # get options
    try:
        opts, args = getopt.getopt(argv, 'hi:',["id="])
    except getopt.GetoptError:
        print(__file__ + " -i <alertIdentifier>")
        sys.exit(2)
    for opt,arg in opts:
        if opt == '-h':
            print(__file__ + " -i <alertIdentifier>")
            sys.exit()
        elif opt in ('-i','--id'):
            alertId = arg



    # get username and password for TheHive
    if not TheHive['username'] and not TheHive['password']:
        TheHive['username'] = input("TheHive Username [%s]: " % getpass.getuser())
        TheHive['password'] = getpass.getpass("TheHive Password: ")

    thapi = TheHiveApi(TheHive['url'],TheHive['username'],
                        TheHive['password'], TheHive['proxies'])



    # Create Zerofox session
    zfapi = ZeroFoxApi(Zerofox)
    response = zfapi.getAlertId(AlertId)

    if(response.status_code == 200):
        import2th(thapi, response.json())
    else:
        print('ko: {}/{}'.format(response.status_code, response.text))
        sys.exit(0)


    # r = zfapi.getApiKey()
    # print(r.status_code)
    # print(r.text)
    #
# zfapi = ZeroFoxApi(Zerofox)
# r = zfapi.getOpenAlerts()
# print(r.status_code)
# print(r.json())




if __name__ == '__main__':
    if len(sys.argv[1:]) > 0:
        run(sys.argv[1:])
    else:
        print(__file__ + " -i <incidentId>")
        sys.exit(2)
