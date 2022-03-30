import requests
from time import sleep
from requests.sessions import urljoin


class BIGIP(object):
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.url = 'https://%s/mgmt/' % self.host
        self.session = requests.Session()
        self.session.auth = (self.username, self.password)
        self.session.verify = False

        # Disable The Annoying Warning Of SSL Verification
        requests.packages.urllib3.disable_warnings()

    def request(self, method, uri='', data=None, filter=None, select=None, top=None, skip=None):
        if isinstance(select, (list, tuple, set)):
            select = ",".join(select)
        return self.session.request(
            method,
            urljoin(self.url, uri),
            json=data, params={
                '$filter': filter, '$select': select, '$top': top, '$skip': skip
            }
        ).json()

    def get(self, uri='', data=None, filter=None, select=None, top=None, skip=None):
        return self.request('GET', uri, data=data, filter=filter, select=select, top=top, skip=skip)

    def post(self, uri='', data=None, filter=None, select=None, top=None, skip=None):
        return self.request('POST', uri, data=data, filter=filter, select=select, top=top, skip=skip)

    def put(self, uri='', data=None, filter=None, select=None, top=None, skip=None):
        return self.request('PUT', uri, data=data, filter=filter, select=select, top=top, skip=skip)

    def delete(self, uri='', data=None, filter=None, select=None, top=None, skip=None):
        return self.request('DELETE', uri, data=data, filter=filter, select=select, top=top, skip=skip)


class ASM(BIGIP):
    def __init__(self, host, username, password):
        super(ASM, self).__init__(host, username, password)
        self.url = urljoin(self.url, 'tm/asm/')

    @property
    def policies(self):
        res = self.get('policies/', select=['id'])
        _policies = []
        for policy in res['items']:
            _policies.append(ASMPolicy(self, policy['id']))
        return _policies

    def policy(self, policy_id):
        return ASMPolicy(self, policy_id)

    def policy_by_name(self, name):
        if not name:
            return None

        res = self.get('policies/', select=['id', 'fullPath'])
        for policy in res['items']:
            if policy['fullPath'].endswith(name):
                return ASMPolicy(self, policy['id'])
        return None

    def events(self, request=None, max_retries=10, delay=1, filter=None, select=None, top=None, skip=None):
        request_url = 'events/requests/'
        if request:
            request_url = urljoin(request_url, str(request))
        for i in range(max_retries):
            res = self.get(request_url, filter=filter, select=select, top=top, skip=skip)
            if res.get('code') != 404:
                return res
            sleep(delay)
        return None


class ASMPolicy(ASM):
    def __init__(self, asm, id):
        super(ASMPolicy, self).__init__(asm.host, asm.username, asm.password)
        self.ASM = asm
        self.id = id
        self.url = urljoin(self.url, 'policies/%s/' % self.id)

    def __repr__(self):
        return 'ASMPolicy(%s)' % self.id

    @property
    def full_path(self):
        return self.get(select='fullPath')['fullPath']

    @property
    def enforcement_mode(self):
        return self.get(select='enforcementMode')['enforcementMode']
