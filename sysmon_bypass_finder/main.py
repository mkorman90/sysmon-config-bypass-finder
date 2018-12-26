import ntpath
import logging
import re
import sys

import click

from lxml import etree, objectify
from tabulate import tabulate


def is_admin_only_path(path):
    """
    This is pretty naive, but seems to do the work for now...
    """
    path = ntpath.splitdrive(path)[1].lower()
    if path.startswith('\\windows') or path.startswith('\\programdata') or path.startswith('\\program files'):
        return True
    return False


def _read_config_to_json(sysmon_config):
    parser = etree.XMLParser(remove_comments=True)
    tree = objectify.parse(sysmon_config, parser=parser)
    root = tree.getroot()
    event_filtering = root.find('EventFiltering')

    configuration = []
    for rule in event_filtering.getchildren():
        rule_type = rule.tag
        on_match = rule.get('onmatch')
        single_rule = {
            'rule_type': rule_type,
            'on_match': on_match,
            'conditions': []
        }
        for condition in rule.iterchildren():
            cond_operator = condition.get('condition')
            cond_content = condition.text
            cond_type = condition.tag
            single_rule['conditions'].append({
                'operator': cond_operator,
                'content': cond_content,
                'condition_type': cond_type
            })
        configuration.append(single_rule)
    return configuration


def _find_possible_bypasses(configuration):
    possible_bypasses = []
    for rule in configuration:

        # We are currently interested only in possible bypasses of execution and exfiltration...
        if rule['rule_type'] not in ['ProcessCreate', 'NetworkConnect']:
            continue

        # We are only interested in exclusions
        if rule['on_match'] != 'exclude':
            continue

        for condition in rule['conditions']:
            operator = condition['operator']
            cond_type = condition['condition_type']
            content = condition['content']

            if operator == 'is':
                # We probabably cannot do anything if this is an exact path,
                # maybe if we have write permissions there...
                continue
            elif operator == 'begin with':
                # Possible bypass if write permissions exist here
                continue
            elif operator == 'contains':
                if not is_admin_only_path(condition['content']):
                    possible_bypasses.append({
                        'rule_type': rule['rule_type'],
                        'description': 'Any {} containing {}'.format(cond_type, content)
                    })
            elif operator == 'end with':
                if rule['rule_type'] == 'ProcessCreate':

                    # For some reason some rules uses ends with but specifies a complete path,
                    # Yet we could do something like: c:\temp\malicious.exe c:\legitimate\excluded\path.exe
                    if re.match(r'\w:\\', content, re.IGNORECASE):
                        continue

                possible_bypasses.append({
                    'rule_type': rule['rule_type'],
                    'description': 'Any {} that ends with {}'.format(cond_type, content)
                })
            elif operator == 'image':
                possible_bypasses.append({
                    'rule_type': rule['rule_type'],
                    'description': 'Any Image with the name {}'.format(content)
                })
            else:
                logging.debug(rule['rule_type'])
                logging.debug(condition)
    return possible_bypasses


@click.command()
@click.argument('sysmon_config', type=click.Path(exists=True))
@click.option('-v', '--verbose', type=click.BOOL, is_flag=True, default=False)
def analyze_config(sysmon_config, verbose):
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG if verbose else logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    logging.debug('Analyzing {}'.format(sysmon_config))

    configuration = _read_config_to_json(sysmon_config)
    possible_bypasses = _find_possible_bypasses(configuration)

    print(tabulate(possible_bypasses, headers='keys'))





