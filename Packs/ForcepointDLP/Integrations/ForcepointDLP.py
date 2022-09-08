# register_module_line('ForcepointDLP', 'start', __line__())
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
from time import strftime
from xmlrpc.client import Boolean
import urllib3
import dateparser
from datetime import datetime
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''


DATE_FORMAT = '%d/%m/%Y, %H:%M:%S'
MAX_INCIDENTS_TO_FETCH = 50
DEFAULT_INDICATORS_THRESHOLD = 65
SEVERITIES = ['LOW', 'MEDIUM', 'HIGH']


''' CLIENT CLASS '''


class Client(BaseClient):

    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def get_access_token(self, username: str, password: str) -> Dict[str, Any]:

        headers = {
            'username': username,
            'password': password
        }

        return self._http_request(
            method='POST',
            url_suffix='/auth/refresh-token',
            headers=headers
        )

    def search_incidents(self, from_date: str, access_token: str,
                         action: Optional[str], status: Optional[str],
                         severity: Optional[str], channel: Optional[str],
                         tag: Optional[str]) -> List[Dict[str, Any]]:

        headers = {
            'Authorization': f"Bearer {access_token}",
            'Content-Type': 'application/json'
        }

        body: Dict[str, Any] = {}
        body['from_date'] = from_date
        body['to_date'] = datetime.now().strftime(DATE_FORMAT)
        body['type'] = 'INCIDENTS'

        if action:
            body['action'] = action

        if status:
            body['status'] = status

        if severity:
            body['severity'] = severity

        if channel:
            body['channel'] = channel

        if tag:
            body['tag'] = tag

        return self._http_request(
            method='POST',
            url_suffix='/incidents',
            headers=headers,
            data=json.dumps(body)
        )

''' HELPER FUNCTIONS '''

def convert_to_demisto_severity(severity: str) -> int:
    return {
        'LOW': IncidentSeverity.LOW,
        'MEDIUM': IncidentSeverity.MEDIUM,
        'HIGH': IncidentSeverity.HIGH
    }[severity]

''' COMMAND FUNCTIONS '''

def get_access_token_command(client: Client, params: Dict[str, Any], test: bool = False) -> str:

    try:
        result = client.get_access_token(
            username=params.get('credentials')['identifier'],
            password=params.get('credentials')['password']
        )

    except:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure username and password are correct and user has sufficient rights'
        else:
            raise e

    if test:
        return 'ok'

    else:
        return result['access_token']

def fetch_incidents(client: Client, access_token: str, last_run: Dict[str, int],
                    first_fetch_time: Optional[int], action: Optional[str],
                    status: Optional[str], min_severity: Optional[str], channel: Optional[str],
                    tag: Optional[str]) -> Tuple[Dict[str, int], List[dict]]:
    
    last_fetch = last_run.get('last_fetch', None)

    if last_fetch is None:
        last_fetch = first_fetch_time
    else:
        last_fetch = int(last_fetch)
    
    latest_created_time = cast(int, last_fetch)

    incidents: List[Dict[str, Any]] = []

    alerts = client.search_incidents(
        access_token=access_token,
        from_date=last_fetch.strftime(DATE_FORMAT),  # TODO: convert last fetch to proper format
        action=action,
        status=status,
        severity=min_severity,
        channel=channel,
        tag=tag
    )

    for alert in alerts:
        incident_created_time = alert.get('incident_time')  # TODO: convert to int time
        incident_created_int = dateparser.parse(incident_created_time, settings={'DATE_ORDER': 'DMY'})
        incident_created_time_ms = incident_created_int * 1000

        if last_fetch:
            if incident_created_time <= last_fetch:
                continue
        
        incident_name = str('Forcepoint DLP Incident ' + alert['id'])

        incident = {
            'name': incident_name,
            'occurred': timestamp_to_datestring(incident_created_time_ms),
            'rawJSON': json.dumps(alert),
            'severity': alert.get('severity', 'Low')
        }

        incidents.append(incident)

        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time
            
    next_run = {'last_fetch': latest_created_time}
    return next_run, incidents

def search_incidents_command(client: Client, access_token: str, args: Dict[str,Any]) -> CommandResults:

    alerts = client.search_incidents(
        access_token=access_token,
        from_date=args.get('from_date'),
        action=args.get('action', None),
        status=args.get('status', None),
        severity=args.get('severity', None),
        channel=args.get('channel', None),
        tag=args.get('tag', None)
    )

    print(alerts)

    return CommandResults(
        outputs_prefix='ForcepointDLP.Incident',
        outputs_key_field='id',
        outputs=alerts
    )


''' MAIN FUNCTION '''

def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = urljoin(params.get('url'), '/dlp/rest/v1')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)


    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    assert isinstance(first_fetch_timestamp, int)

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy
        )

        if command != 'test-module':
            token = get_access_token_command(client,params)

        if command == 'test-module':
            result = get_access_token_command(client,params,test=True)
            print(result)
            return_results(result)

        elif command == 'fetch-incidents':
            max_results = arg_to_number(
                arg=params.get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH
            
            next_run, incidents = fetch_incidents(
                client=client,
                access_token=token,
                max_results=max_results,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_timestamp,
                min_severity=args.get('fetch_severity', None),
                action=args.get('fetch_action', None),
                status=args.get('fetch_status', None)
            )

            print(next_run)
            print(incidents)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)


        elif command == 'forcepointdlp-search-incidents':
            result = search_incidents_command(client, token, args)
            print(result)
            return_results(result)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')

''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

#register_module_line('ForcepointDLP', 'end', __line__())
