#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals
import json

class zf2markdown():

    def __init__(self, c):

        self.taskLog = "{0}{1}{2}{3}".format(
            "#### General Information ####\n\n**Alert type:** {0}\n\n**Date :** {1}\n\n**Target name:** {2}\n\n**network:** {3}\n\n**rule name:** {4}\n\n**Suspicious content:** {5}\n\n".format(
                c.get('alert_type'),
                c.get('timestamp'),
                c.get('entity').get('name'),
                c.get('network'),
                c.get('rule_name'),
                c.get('offending_content_url')
            ), "----\n\n#### Entity Information\n\n{}\n\n".format(self.entity(c.get('entity'))),
            "----\n\n#### Perpetrator  Information\n\n{}\n\n".format(self.perpetrator(c.get('perpetrator'))),
            "----\n\n#### Metadata\n\n{}\n\n".format(self.metadata(c.get('metadata'))),
        )

        self.generalInfo = "#### General Information ####\n\n**Alert type:** {0}\n\n**Date :** {1}\n\n**Target name:** {2}\n\n**network:** {3}\n\n**rule name:** {4}\n\n**Suspicious content:** {5}\n\n".format(
                c.get('alert_type'),
                c.get('timestamp'),
                c.get('entity').get('name'),
                c.get('network', None),
                c.get('rule_name', None),
                c.get('offending_content_url', None)
            )

        self.entityInfo = "#### Entity Information\n\n{}\n\n".format(self.entity(c.get('entity')))

        self.perpetratorInfo = "#### Perpetrator Information\n\n{}\n\n".format(self.perpetrator(c.get('perpetrator')))

        self.metadata = "#### Metadata\n\n{}\n\n".format(self.metadata(c.get('metadata')))

    def entity(self,c):
        return "{0}".format(
            "**Entity Name: ** {0}\n\n**Entity Id: **{1}\n\n**Entity Image: **{2}\n\n".format(
                c.get('name'),
                c.get('id'),
                c.get('image'))
        )



    def perpetrator(self,c):
        return "{}".format(
               "**Username: ** {0}\n\n**Display Name: **{1}\n\n**Account Number: **{2}\n\n**URL: **{3}\n\n**Date: **{4}\n\n**Image: **{5}\n\n**Type: **{6}\n\n**Id: **{7}\n\n**Network: **{8}\n\n".format(
                     c.get('username',"None"),
                     c.get('display_name',"None"),
                     c.get('account_number',"None"),
                     c.get('url',"None"),
                     c.get('timestamp',"None"),
                     c.get('image',"None"),
                     c.get('type',"None"),
                     c.get('id',"None"),
                     c.get('network', "None")
                 )
        )


    def asset(self,c):
        return "{}".format(
            "**Entity Name: **{0}\n\n**Entity Id: **{1}\n\n**Entity Image: **{2}\n\n".format(
                c.get('name'),
                c.get('id'),
                c.get('image')
            )
        )

    def addData(self, title, content, key):
        if content and content.get(key):
            return "**{}:**\ {}\n\n".format(title, content[key])
        else:
            return ""


    def metadata(self,c):
        if json.loads(c).get('occurrences'):
            occurrences = json.loads(c).get('occurrences')
        else:
            occurrences = None

        meta = json.loads(c)
        raw = json.loads(c).get('content_raw_data')

        # metadata = self.addMetadata("Matching Name", raw, 'name')
        metadata = self.addData("Matching Name", raw, 'name') + \
            self.addData("Matching Name", raw, 'name') + \
            self.addData("Entity Id", raw, 'id') + \
            self.addData("Content type", meta, 'content_type') + \
            self.addData("Content URL", meta, 'content_url') +\
            self.addData("Page Name", raw, 'content_url') + \
            self.addData("Description", raw, 'global_brand_page_name') + \
            self.addData("Page Name", raw, 'description')



            # METADATA
            # Offending Content
            # User

            #     return "{}".format(
            # "**Matching Name: **{0}\n\n"
            # "**Entity Id: **{1}\n\n"
            # "**Content type: **{2}\n\n"
            # "**Content URL: **{3}\n\n"
            # "**Page Name: **{4}\n\n"
            # "**Description**\n\n{5}"
            # "**Offending Content**\n\n"
            # "Terms: {6}\n\n"
            # "Text: {7}\n\n".format(
            #     raw.get('name',"None"),
            #     raw.get('id', "None"),
            #     json.loads(c).get('content_type', None),
            #     json.loads(c).get('content_url', None),
            #     raw.get('global_brand_page_name', "None"),
            #     raw.get('description', "None"),
            #     type(occurrences),
        return metadata

                # raw.get('offending_content',"None").get('term', "None"),
                # raw.get('offending_conten   t', "None").get('text', "None")
        #     )
        # )

def thCaseDescription(c):

    """
        Build Case summary

        :param is dict content(alert)
    """

    summary = "**Alert type:** {0}\n\n**Date :** {1}\n\n**Target name:** {2}\n\n**network:** {3}\n\n**rule name:** {4}\n\n**Suspicious content:** {5}".format(
                        c.get('alert_type'),
                        c.get('timestamp'),
                        c.get('entity').get('name'),
                        c.get('network'),
                        c.get('rule_name'),
                        c.get('offending_content_url')

                    )

    description = "{}\n\n---\n{}\n\n".format(
        summary,
        zf2markdown(c).taskLog


    )

    return description


def thTitle(c):
    return "[Zerofox] {0} in {1} for entity: {2}".format(
        c.get("alert_type","-"),
        c.get("network", "-"),
        c.get("entity",{}).get("name","-")
        )
