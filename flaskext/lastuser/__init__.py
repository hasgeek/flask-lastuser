# -*- coding: utf-8 -*-
"""
    flaskext.lastuser
    ~~~~~~~~~~~~~~~~~

    Flask extension for LastUser

    :copyright: (c) 2011 by HasGeek Media LLP.
    :license: BSD, see LICENSE for more details.
"""

from __future__ import absolute_import
from functools import wraps
import uuid
from base64 import urlsafe_b64encode
import urlparse
import httplib2
import urllib

from flask import session, g, redirect, url_for, request, json


class LastUserConfigException(Exception):
    pass

class LastUserException(Exception):
    pass


def randomstring():
    return urlsafe_b64encode(uuid.uuid4().bytes).rstrip('=')


class UserInfo(object):
    """
    User info object that is inserted into the context variable container.
    """
    def __init__(self, userid, username, fullname, email=None):
        self.userid = userid
        self.username = username
        self.fullname = fullname
        self.email = email


class LastUser(object):
    """
    Flask extension for LastUser
    """
    def __init__(self, app=None):
        self.app = app

        self._loginhandler = None
        self._logouthandler = None
        self._authhandler = None
        self._redirect_uri_name = None
        self._autherrorhandler = None
        self._servicehandler = None

        self.lastuser_server = None
        self.auth_endpoint = None
        self.token_endpoint = None
        self.client_id = None
        self.client_secret = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        self.lastuser_server = app.config['LASTUSER_SERVER']
        self.auth_endpoint = app.config.get('LASTUSER_ENDPOINT_AUTH', 'auth')
        self.token_endpoint = app.config.get('LASTUSER_ENDPOINT_TOKEN', 'token')
        self.client_id = app.config['LASTUSER_CLIENT_ID']
        self.client_secret = app.config['LASTUSER_CLIENT_SECRET']

        self.app.before_request(self.before_request)

    def make_client(self):
        return Client2(self.client_id, self.client_secret, self.lastuser_server)

    def before_request(self):
        info = session.get('lastuser_userinfo')
        if info is not None:
            user = UserInfo(userid = info.get('userid'),
                            username = info.get('username'),
                            fullname = info.get('fullname'),
                            email = info.get('email'))
            g.user = user
        else:
            g.user = None

    def loginhandler(self, f):
        """
        Decorator for login handler route.
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            data = f(*args, **kwargs)
            if not self._redirect_uri_name:
                raise LastUserConfigException("No authorization handler defined")
            session['lastuser_state'] = randomstring()
            session['lastuser_redirect_uri'] = url_for(self._redirect_uri_name,
                    next=request.args.get('next') or request.referrer or None,
                    _external=True)
            client = self.make_client()
            return redirect(client.authorization_url(
                redirect_uri = session['lastuser_redirect_uri'],
                endpoint = self.auth_endpoint,
                params = {'response_type': 'code',
                          'scope': data.get('scope', 'id'),
                          'state': session['lastuser_state']},
                ))
        self._loginhandler = f
        return decorated_function

    def logouthandler(self, f):
        """
        Decorator for logout handler route.
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            result = f(*args, **kwargs)
            g.user = None
            session.pop('lastuser_userinfo', None)
            return result
        self._logouthandler = f
        return decorated_function

    def authhandler(self, f):
        """
        Set the login cookies.
        """
        @wraps(f)
        def decorated_function(*args, **kw):
            if not self._autherrorhandler:
                raise LastUserConfigException("No authorization error handler")
            state = request.args.get('state')
            if state is None or state != session.get('lastuser_state'):
                return self._autherrorhandler(error='csrf_invalid')
            if 'error' in request.args:
                return self._autherrorhandler(
                    error = request.args['error'],
                    error_description = request.args.get('error_description'),
                    error_uri = request.args.get('error_uri'))
            code = request.args.get('code')
            if not code:
                return self._autherrorhandler(error='code_missing')
            client = self.make_client()
            result = client.access_token(code,
                redirect_uri = session.get('lastuser_redirect_uri'),
                endpoint = self.token_endpoint,
                grant_type = 'authorization_code',
                params = {'scope': 'id'})
            userinfo = result.get('userinfo')
            session['lastuser_userinfo'] = userinfo
            if userinfo is not None:
                g.user = UserInfo(userinfo.get('userid'), userinfo.get('username'),
                    userinfo.get('fullname'), userinfo.get('email'))
            return f(*args, **kw)
        self._authhandler = f
        self._redirect_uri_name = f.__name__
        return decorated_function

    def autherrorhandler(self, f):
        """
        Handler for authorization errors
        """
        @wraps(f)
        def decorated_function(error, error_description=None, error_uri=None):
            return f(error, error_description, error_uri)
        self._autherrorhandler = f
        return decorated_function

    def servicehandler(self, f):
        """
        Handler for service requests from LastUser, used to notify of new
        resource access tokens and user info changes.
        """
        @wraps(f)
        def decorated_function(*args, **kw):
            return f(*args, **kw)
        self._servicehandler = f
        return decorated_function

# OAuth2 Client2 class adapted from https://github.com/OfflineLabs/python-oauth2/
# We use our own copy since there's no standard Python OAuth2 implementation
class Client2(object):
    """Client for OAuth 2.0 draft spec
    https://svn.tools.ietf.org/html/draft-hammer-oauth2-00
    """

    def __init__(self, client_id, client_secret, oauth_base_url,
        redirect_uri=None, cache=None, timeout=None, proxy_info=None):

        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.oauth_base_url = oauth_base_url

        if self.client_id is None or self.client_secret is None or \
           self.oauth_base_url is None:
            raise ValueError("Client_id and client_secret must be set.")

        self.http = httplib2.Http(cache=cache, timeout=timeout,
            proxy_info=proxy_info)

    def authorization_url(self, redirect_uri=None, params=None, state=None,
        immediate=None, endpoint='authorize'):
        """Get the URL to redirect the user for client authorization
        https://svn.tools.ietf.org/html/draft-hammer-oauth2-00#section-3.5.2.1
        """

        # prepare required args
        args = {
            'response_type': 'code',
            'client_id': self.client_id,
        }

        # prepare optional args
        redirect_uri = redirect_uri or self.redirect_uri
        if redirect_uri is not None:
            args['redirect_uri'] = redirect_uri
        if state is not None:
            args['state'] = state
        if immediate is not None:
            args['immediate'] = str(immediate).lower()

        args.update(params or {})

        return '%s?%s' % (urlparse.urljoin(self.oauth_base_url, endpoint),
            urllib.urlencode(args))

    def access_token(self, code, redirect_uri, grant_type=None,
        endpoint='access_token', params=None):
        """Get an access token from the supplied code
        https://svn.tools.ietf.org/html/draft-hammer-oauth2-00#section-3.5.2.2
        """

        # prepare required args
        if code is None:
            raise ValueError("Code must be set.")
        if redirect_uri is None:
            raise ValueError("Redirect_uri must be set.")
        args = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': redirect_uri,
        }

        # prepare optional args
        if grant_type is not None:
            args['grant_type'] = grant_type

        args.update(params or {})

        uri = urlparse.urljoin(self.oauth_base_url, endpoint)
        #uri = '%s?%s' % (uri, urllib.urlencode(args))

        response, content = self.http.request(uri, "POST",
            headers = {'Content-type': 'application/x-www-form-urlencoded'},
            body = urllib.urlencode(args))

        # TODO: Do something intelligent if there's an error (response['status'] != 200)
        response_args = json.loads(content)

        return response_args


    def request(self, base_uri, access_token=None, method='GET', body=None,
        headers=None, params=None, token_param='oauth_token'):
        """Make a request to the OAuth API"""

        args = {}
        args.update(params or {})
        if access_token is not None and method == 'GET':
            args[token_param] = access_token
        elif access_token is None and method == 'GET':
            args.update({
                'client_id': self.client_id,
                'client_secret': self.client_secret,
            })

        uri = '%s?%s' % (base_uri, urllib.urlencode(args))
        return self.http.request(uri, method=method, body=body, headers=headers)