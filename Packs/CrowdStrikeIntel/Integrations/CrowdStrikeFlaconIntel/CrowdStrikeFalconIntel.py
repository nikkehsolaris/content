from typing import Dict, Tuple, List

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from datetime import datetime

import urllib3
import traceback

# Disable insecure warnings
urllib3.disable_warnings()


class Client:
    """
    bla bla
    """
    def __init__(self, params):
        self._cs_client = CrowdStrikeClient(params=params)
        self._threshold = params.get('threshold')
        self.query_params = ['offset', 'limit', 'sort', 'q', 'query']
        self.date_params = {
            'created_date': {'operator': '', 'raw_name': 'created_date'},
            'max_last_modified_date': {'operator': '<=', 'api_key': 'last_modified_date'},
            'min_last_activity_date': {'operator': '>=', 'api_key': 'first_activity_date'},
            'max_last_activity_date': {'operator': '<=', 'api_key': 'last_activity_date'}
        }

    def build_params(self, args: dict) -> dict:
        params = {key: args.get(key) for key in self.query_params}
        params['filter'] = self.build_filter_query(args)
        return assign_params(**params)

    @staticmethod
    def date_to_epoch(date: str) -> int:
        return int(datetime.fromisoformat(date).timestamp())

    def build_filter_query(self, args: dict) -> str:
        filter_query = str()

        for key in args:
            if key not in self.query_params:
                if key not in self.date_params:
                    values = argToList(args[key], ',')
                    for value in values:
                        filter_query += f"{key}:'{value}'+"
                else:
                    operator = self.date_params.get(key, {}).get('operator')
                    api_key = self.date_params.get(key, {}).get('api_key')
                    filter_query += f"{api_key}:{operator}{self.date_to_epoch(args[key])}+"

        if filter_query.endswith('+'):
            filter_query = filter_query[:-1]

        return filter_query

    def check_quota_status(self):
        return self._cs_client.check_quota_status()

    def file(self):
        pass

    def ip(self):
        pass

    def url(self):
        pass

    def domain(self):
        pass

    def cs_actors(self, args):
        return self._cs_client.http_request('GET', 'intel/combined/actors/v1', params=self.build_params(args))

    def cs_indicators(self, args):
        return self._cs_client.http_request('GET', 'intel/combined/indicators/v1', params=self.build_params(args))

    def cs_reports(self, args):
        return self._cs_client.http_request('GET', 'intel/combined/reports/v1', params=self.build_params(args))

    def cs_report_pdf(self):
        pass


def test_module(client: Client):
    """
    If a client is successfully constructed then an accesses token was successfully reached,
    therefore the username and password are valid and a connection was made.
    Additionally, checks if not using all the optional quota and check that an http request to actors & indicators
    endpoints in successful.
    :param client: the client object with an access token
    :return: ok if got a valid accesses token and not all the quota is used at the moment
    """
    output = client.check_quota_status()

    error = output.get('errors')
    if error:
        return error[0]

    meta = output.get('meta')
    if meta is not None:
        quota = meta.get('quota')
        if quota is not None:
            total = quota.get('total')
            used = quota.get('used')
            if total <= used:
                raise Exception(f'Quota limitation has been reached: {used}')
            else:
                client._cs_client.http_request('GET', 'intel/combined/indicators/v1', params={'limit': 1})
                client._cs_client.http_request('GET', 'intel/combined/actors/v1', params={'limit': 1})
                return 'ok'
    raise Exception('Quota limitation is unreachable')


def file_command(client: Client):
    pass


def ip_command(client: Client):
    pass


def url_command(client: Client):
    pass


def domain_command(client: Client):
    pass


def cs_actors_command(client: Client):
    res = client.cs_actors(demisto.args())
    resources = res.get('resources', {})

    if not resources:
        return 'No actors found.', {}, res

    md = '## Falcon Intel Actor search\n'
    for r in resources:
        image_url = r.get('image', {}).get('url')
        name = r.get('name')
        actor_id = r.get('id')
        url = r.get('url')
        slug = r.get('slug')
        short_description = r.get('short_description')
        first_activity_date = r.get('first_activity_date')
        last_activity_date = r.get('last_activity_date')
        active = r.get('active')
        known_as = r.get('known_as')
        target_industries = r.get('target_industries')
        target_countries = r.get('target_countries')
        origins = r.get('origins')
        motivations = r.get('motivations')
        capability = r.get('capability', {}).get('value')
        group = r.get('group')
        region = r.get('region', {}).get('value')
        kill_chain = r.get('kill_chain')

        if image_url:
            md += '![' + name + '](' + image_url + ' "' + name + '")\n'

        md += '### ' + name + '\n'
        md += 'ID: [' + str(actor_id) + '](' + url + ')\n'
        md += 'Slug: ' + slug + '\n'
        md += 'Short description: ' + short_description + '\n'
        md += 'First/Last activity: ' + timestamp_to_datestring(first_activity_date) + ' / ' + \
              timestamp_to_datestring(last_activity_date) + '\n'
        md += 'Active: ' + str(active) + '\n' if active is not None else ''
        md += 'Known as: ' + known_as + '\n' if known_as else ''
        md += '- Target industries: ' + get_values(target_industries) + '\n' if target_industries else ''
        md += '- Target countries: ' + get_values(target_countries) + '\n' if target_countries else ''
        md += '- Origins: ' + get_values(origins) + '\n' if origins else ''
        md += '- Motivations: ' + get_values(motivations) + '\n' if motivations else ''
        md += '- Capability: ' + capability + '\n' if capability else ''
        md += '- Group: ' + group + '\n' if group else ''
        md += '- Region: ' + region + '\n' if region else ''

        if kill_chain:
            md += '#### Kill chain\n'
            for kc_field in kill_chain:
                if 'rich_text' in kc_field and kc_field.index('rich_text') == 0:
                    continue
                md += '- ' + string_to_table_header(kc_field) + ': ' + kill_chain.get(kc_field)
            md += '\n'

    return md, {}, res


def get_values(l: list) -> str:
    nl = [i.get('value') for i in l]
    return ', '.join(nl)


def cs_indicators_command(client: Client):
    pass


def cs_reports_command(client: Client):
    res = client.cs_reports(demisto.args())
    resources = res.get('resources', {})

    if not resources:
        return 'No reports found.', {}, res

    md = '## Falcon Intel Report search\n'
    for r in resources:
        report_id = r.get('id')
        url = r.get('url')
        name = r.get('name')
        report_type = r.get('type', {}).get('name')
        sub_type = r.get('sub_type', {}).get('name')
        slug = r.get('slug')
        created_date = r.get('created_date')
        last_modified_date = r.get('last_modified_date')
        short_description = r.get('short_description')
        target_industries = r.get('target_industries')
        target_countries = r.get('target_countries')
        motivations = r.get('motivations')
        tags = r.get('tags')

        md += '### ' + name + '\n'
        md += 'ID: [' + str(report_id) + '](' + url + ')\n'
        md += 'Type: ' + report_type + '\n'
        md += 'Sub type: ' + sub_type + '\n'
        md += 'Slug: ' + slug + '\n'
        md += 'Created: ' + timestamp_to_datestring(created_date) + '\n'
        md += 'Last modified: ' + timestamp_to_datestring(last_modified_date) + '\n'
        md += 'Description: ' + short_description + '\n'
        md += '- Target industries: ' + get_values(target_industries) + '\n' if target_industries else ''
        md += '- Target countries: ' + get_values(target_countries) + '\n' if target_countries else ''
        md += '- Motivations: ' + get_values(motivations) + '\n' if motivations else ''
        md += '- Tags: ' + get_values(tags) + '\n' if motivations else ''

    return md, {}, res


def cs_report_pdf_command(client: Client):
    pass


def main():
    params = demisto.params()
    try:
        command = demisto.command()
        LOG(f'Command being called in CrowdStrikeFalconX Sandbox is: {command}')
        client = Client(params=params)
        if command == 'test-module':
            return_outputs(test_module(client))
        elif command == 'file':
            hr, ops, raw = file_command(client)
            return_outputs(hr, ops, raw)
        elif command == 'ip':
            hr, ops, raw = ip_command(client)
            return_outputs(hr, ops, raw)
        elif command == 'url':
            hr, ops, raw = url_command(client)
            return_outputs(hr, ops, raw)
        elif command == 'domain':
            hr, ops, raw = domain_command(client)
            return_outputs(hr, ops, raw)
        elif command == 'cs-actors':
            hr, ops, raw = cs_actors_command(client)
            return_outputs(hr, ops, raw)
        elif command == 'cs-indicators':
            hr, ops, raw = cs_indicators_command(client)
            return_outputs(hr, ops, raw)
        elif command == 'cs-reports':
            hr, ops, raw = cs_reports_command(client)
            return_outputs(hr, ops, raw)
        elif command == 'cs-report-pdf':
            hr, ops, raw = cs_report_pdf_command(client)
            return_outputs(hr, ops, raw)
        else:
            raise NotImplementedError(f'{command} is not an existing CrowdStrike Falcon Intel command')
    except Exception as err:
        return_error(f'Unexpected error:\n{str(err)}', error=traceback.format_exc())


from CrowdStrikeApiModule import *  # noqa: E402

if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
