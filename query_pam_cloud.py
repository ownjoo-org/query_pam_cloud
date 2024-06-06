import argparse
import json

from typing import Optional, Generator
from requests import Session, Response, HTTPError

PAGE_SIZE: int = 1000

URL_BASE: str = 'https://{{subdomain}}.privilegecloud.cyberark.com/PasswordVault/API'
URL_LOGON: str = 'https://{tenant_id}.id.cyberark.cloud/oauth2/platformtoken'
URL_ACCOUNTS: str = f'{URL_BASE}/Accounts'


def logon(session: Session, tenant_id: str, client_id: str, client_secret: str) -> str:
    logon_url: str = URL_LOGON.format(tenant_id=tenant_id)
    post_data: dict = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
    }
    resp_auth: Response = session.post(url=logon_url, data=post_data)
    resp_auth.raise_for_status()
    token: str = resp_auth.json().get('access_token')
    return token


def list_accounts(session: Session, subdomain: str, search: Optional[str] = None) -> Generator[dict, None, None]:
    params: dict = {
        'offset': 0,
        'limit': PAGE_SIZE,
    }
    if search:
        params['search'] = search
    while True:
        resp_accounts: Response = session.get(url=URL_ACCOUNTS.format(subdomain=subdomain), params=params)
        resp_accounts.raise_for_status()
        data: dict = resp_accounts.json()
        accounts: list = data.get('value')
        yield from accounts
        if len(accounts) < PAGE_SIZE:
            break
        params['offset'] += PAGE_SIZE


def main(
        domain: str,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        search: str,
        proxies: Optional[dict] = None,
) -> Generator[dict, None, None]:
    session = Session()

    headers: dict = {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    session.headers = headers
    session.proxies = proxies

    token: None | str = None
    try:
        token = logon(
            session=session,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        session.headers.update(
            {
                'Content-Type': 'application/json; Charset=UTF-8',
                'concurrentSession': True,
                'Authorization': f'Bearer {token}',
            }
        )
    except HTTPError as http_err:
        print(f'HTTPError during logon: {http_err}')
        raise
    except Exception as exc_auth:
        print(f'Unexpected error during logon: {exc_auth}')
        raise

    try:
        yield from list_accounts(session=session, subdomain=domain, search=search)
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
        '--tenant_id',
        type=str,
        required=True,
        help="""The tenant ID for your instance in privilege cloud.
        Usually 6 characters to be pre-pended to the cyberark URL (abc123.id.cyberark.cloud)""",
    )
    parser.add_argument(
        '--client_id',
        default=None,
        type=str,
        required=True,
        help='The user name for your CyberArk PAM account',
    )
    parser.add_argument(
        '--client_secret',
        default=None,
        type=str,
        required=True,
        help='The password for your CyberArk PAM account',
    )
    # parser.add_argument(
    #     '--auth_method',
    #     default='cyberark',
    #     type=str,
    #     required=True,
    #     help='The authentication method for your CyberArk account',
    #     choices=['Cyberark', 'LDAP', 'RADIUS'],
    # )
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
        tenant_id=args.tenant_id,
        client_id=args.client_id,
        client_secret=args.client_secret,
        # auth_method=args.auth_method,
        search=args.search,
        proxies=proxies,
    ):
        print(json.dumps(asset, indent=4))
    else:
        print('No results found')
