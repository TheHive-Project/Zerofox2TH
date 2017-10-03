#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json


class zf2markdown():

    def __init__(self, c, thumbnails):

        self.entity_image = thumbnails.get("entity_image")
        self.perpetrator_image = thumbnails.get("perpetrator_image")
        self.generalInfo = "### General Information\n\n" \
                           "***\n\n" \
                           "- **Alert type**: {0}\n\n" \
                           "- **Date**: {1}\n\n" \
                           "- **Target name:** {2}\n\n" \
                           "- **network:** {3}\n\n" \
                           "- **rule name:** {4}\n\n" \
                           "- **Suspicious content:** {5}\n\n".format(
                c.get('alert_type'),
                c.get('timestamp'),
                c.get('entity').get('name'),
                c.get('network', None),
                c.get('rule_name', None),
                c.get('offending_content_url', None)
            )

        self.entityInfo = "### Entity Information\n\n" \
                          "***\n\n" \
                          "{}\n\n".format(self.entity(c.get('entity')))

        self.perpetratorInfo = "### Perpetrator Information\n\n" \
                               "***\n\n" \
                               "{}\n\n".format(self.perpetrator(c.get('perpetrator')))

        self.metadataInfo = "### Metadata\n\n" \
                        "***\n\n" \
                        "```\n\n" \
                        "{}\n\n" \
                        "```\n\n".format(self.metadata(c.get('metadata')))

        self.description = "{0}{1}{2}{3}".format(self.generalInfo,
                                                 self.entityInfo,
                                                 self.perpetratorInfo,
                                                 self.metadataInfo)


    def entity(self, c):
        return "- **Entity Name**:  {0}\n\n" \
               "- **Entity Id**: {1}\n\n" \
               "- **Entity Image (resized)**: ![][entity]\n\n[entity]: {2}\n\n".format(
                c.get('name'),
                c.get('id'),
                self.entity_image)


    def perpetrator(self,c):

        return "- **Username**: {0}\n\n" \
               "- **Display Name**: {1}\n\n" \
               "- **Account Number**: {2}\n\n" \
               "- **URL**: {3}\n\n" \
               "- **Date**: {4}\n\n" \
               "- **Image (resized)**: ![][perpetrator]\n\n[perpetrator]: {5}\n\n" \
               "- **Type**: {6}\n\n" \
               "- **Id**: {7}\n\n" \
               "- **Network**: {8}\n\n".format(
                     c.get('username',"None"),
                     c.get('display_name',"None"),
                     c.get('account_number',"None"),
                     c.get('url',"None"),
                     c.get('timestamp',"None"),
                     self.perpetrator_image,
                     c.get('type',"None"),
                     c.get('id',"None"),
                     c.get('network', "None")
                 )

    def asset(self, c):
        return "- **Entity Name**: {0}\n\n" \
               "- **Entity Id**: {1}\n\n" \
               "- **Entity Image**: ![][asset]\n\n[asset]: {2}\n\n".format(
                c.get('name'),
                c.get('id'),
                self.entity_image
            )

    def addData(self, title, content, key):
        if content and content.get(key):
            return "**{}:**\ {}\n\n".format(title, content[key])
        else:
            return ""

    def metadata(self, c):
        try:
            raw = json.loads(c, strict=False).get('content_raw_data', None)
        except json.decoder.JSONDecodeError:
            raw = None
            pass
        if raw:
            return json.dumps(raw, indent=4, sort_keys=True)
        else:
            return "None"


def th_case_description(c, thumbnails):

    """
        Build Case summary

        :param is dict content(alert)
    """

    description = "{}".format(
        zf2markdown(c, thumbnails).description
    )

    return description


def th_title(c):
    return "[Zerofox] {0} in {1} for entity: {2}".format(
        c.get("alert_type", "-"),
        c.get("network", "-"),
        c.get("entity", {}).get("name", "-")
        )
