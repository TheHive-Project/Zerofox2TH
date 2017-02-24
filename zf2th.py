#!/usr/bin/env python3
# -*- coding: utf-8 -*-



from __future__ import print_function
from __future__ import unicode_literals

import sys
import getopt
import json
import getpass

from Zerofox.api import ZeroFoxApi
from config import Zerofox, TheHive
from theHive4py.api import TheHiveApi
from theHive4py.models import Case,CaseTask,CaseTaskLog
from zf2markdown import zf2markdown






def addTags(tags, content):

    """
        add tag to tags

        :param tags is list
        :param content is list
    """

    for newtag in content:
        tags.append("ZF:{}".format(newtag))
    return tags

def thCaseDescription(c):

    """
        Build Case summary

        :param is dict content(alert)
    """

    description = "**Alert type:** {0}\n\n**Date :** {1}\n\n**Target name:** {2}\n\n**network:** {3}\n\n**rule name:** {4}\n\n**Suspicious content:** {5}".format(
                        c.get('alert_type'),
                        c.get('timestamp'),
                        c.get('entity').get('name'),
                        c.get('network'),
                        c.get('rule_name'),
                        c.get('offending_content_url')

                    )

    return description



def thTitle(content):
    return "[Zerofox] #{0} - {1} in {2} for entity: {3}".format(
        content.get("id", "-"),
        content.get("alert_type","-"),
        content.get("network", "-"),
        content.get("entity",{}).get("name","-")
        )

def thSeverity(sev):

    """
        convert DigitalShadows severity in TH severity

        :sev string
    """

    severities = {
        'NONE':1,
        1:1,
        2:1,
        3:2,
        4:3
    }
    return severities[sev]


def convertDs2ThCase(content):

    """
        convert Zerofox alert in a TheHive Case

        :content dict object
    """
    if content.get('alert'):
        c = content.get('alert')
    else:
        return "Can't open alert"
        sys.exit(1)

    tasks = []
    tags = ["src:ZeroFOX"]
    tags = addTags(tags,[
        c.get("alert_type"),
        c.get("network"),
        c.get("entity",{}).get("name","-"),
        "id={}".format(c.get('id'))
        ])

    case = Case(
            title=thTitle(c),
            tlp=2,
            severity=thSeverity(c.get('severity',"3")),
            flag=False,
            tags=tags,
            description = thCaseDescription(c)
    )

    return case


def caseAddTask(thapi, caseId, content):
    """

    :param thapi: requests session
    :param caseId: text  is id of the task
    :param c: json as Zerofox content(alert)
    :return:
    """
    if content.get('alert'):
        c = content.get('alert')
    else:
        return "Can't open alert"
        sys.exit(1)

    task = CaseTask(
        title="Alert #{} imported from Zerofox".format(c.get('id')),
        description="Incident from Zerofox"
    )

    m = zf2markdown(c).taskLog
    log = CaseTaskLog(message=m)
    thresponse = thapi.create_case_task(caseId, task)
    r = thresponse.json()
    thresponse = thapi.create_task_log(r['id'], log)


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
    response = zfapi.getAlertId(alertId)

    if(response.status_code == 200):
        import2th(thapi, response.json())
    else:
        print('ko: {}/{}'.format(response.status_code, response.text))
        sys.exit(0)


if __name__ == '__main__':
    if len(sys.argv[1:]) > 0:
        run(sys.argv[1:])
    else:
        print(__file__ + " -i <incidentId>")
        sys.exit(2)
