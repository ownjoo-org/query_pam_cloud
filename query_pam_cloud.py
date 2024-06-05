import argparse
import json

from typing import Optional, Generator
from requests import Session, Response, HTTPError

PAGE_SIZE: int = 1000

URL_BASE: str = 'https://{{subdomain}}.privilegecloud.cyberark.com/PasswordVault/API'
URL_LOGON: str = f'{URL_BASE}/auth/{{auth_method}}/Logon/'
URL_ACCOUNTS: str = f'{URL_BASE}/Accounts'


def logon(session: Session, domain: str, username: str, password: str, auth_method) -> str:
    logon_url: str = URL_LOGON.format(subdomain=domain, auth_method=auth_method)
    post_data: dict = {'username': username, 'password': password}
    resp_auth: Response = session.post(url=logon_url, data=post_data)
    resp_auth.raise_for_status()
    # API doc says token will be in format {"the_token_value"}
    token: str = resp_auth.text.replace('{', '').replace('}', '')
    return token


def list_accounts(session: Session, search: Optional[str] = None) -> Generator[dict, None, None]:
    params: dict = {
        'offset': 0,
        'limit': PAGE_SIZE,
    }
    if search:
        params['search'] = search
    while True:
        resp_accounts: Response = session.get(url=URL_ACCOUNTS, params=params)
        resp_accounts.raise_for_status()
        data: dict = resp_accounts.json()
        accounts: list = data.get('value')
        yield from accounts
        if len(accounts) < PAGE_SIZE:
            break
        params['offset'] += PAGE_SIZE


def main(
        domain: str,
        username: str,
        password: str,
        auth_method: str,
        search: str,
        proxies: Optional[dict] = None,
) -> Generator[dict, None, None]:
    session = Session()

    headers: dict = {
        'Accept': 'application/json',
        'Content-Type': 'application/json; Charset=UTF-8',
        'concurrentSession': True,
    }
    session.headers = headers
    session.proxies = proxies

    token: None | str = None
    try:
        token = logon(session=session, domain=domain, username=username, password=password, auth_method=auth_method)
        session.headers.update({'Authorization': token})
    except HTTPError as http_err:
        print(f'HTTPError during logon: {http_err}')
        raise
    except Exception as exc_auth:
        print(f'Unexpected error during logon: {exc_auth}')
        raise

    try:
        yield from list_accounts(session=session, search=search)
    except HTTPError as http_err:
        print(f'HTTPError during accounts retrieval: {http_err}')
        raise
    except Exception as exc_auth:
        print(f'Unexpected error during accounts retrieval: {exc_auth}')
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--subdomain',
        type=str,
        required=True,
        help="The subdomain name for your instance in privilege cloud (subdomain.privilegecloud.cyberark.com)",
    )
    parser.add_argument(
        '--username',
        default=None,
        type=str,
        required=True,
        help='The user name for your CyberArk PAM account',
    )
    parser.add_argument(
        '--password',
        default=None,
        type=str,
        required=True,
        help='The password for your CyberArk PAM account',
    )
    parser.add_argument(
        '--auth_method',
        default='cyberark',
        type=str,
        required=True,
        help='The authentication method for your CyberArk account',
        choices=['Cyberark', 'LDAP', 'RADIUS'],
    )
    parser.add_argument(
        '--search',
        type=str,
        required=False,
        help='List of keywords to search for in accounts separated by a space (ie. "Windows admin")',
    )
    parser.add_argument(
        '--proxies',
        type=str,
        required=False,
        help="JSON structure specifying 'http' and 'https' proxy URLs",
    )

    args = parser.parse_args()

    proxies: Optional[dict] = None
    if proxies:
        try:
            proxies: dict = json.loads(args.proxies)
        except Exception as exc_json:
            print(f'WARNING: failure parsing proxies: {exc_json}: proxies provided: {proxies}')

    for asset in main(
        domain=args.subdomain,
        username=args.username,
        password=args.password,
        auth_method=args.auth_method,
        search=args.search,
        proxies=proxies,
    ):
        print(json.dumps(asset, indent=4))
    else:
        print('No results found')