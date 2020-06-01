from flask import Flask, request, abort
from functools import wraps
import json
from jose import jwt
from urllib.request import urlopen

app = Flask(__name__)

AUTH0_DOMAIN =  #@TODO_REPLACE_WITH_YOUR_DOMAIN #Your Auth0 host url
ALGORITHMS = ['RS256']
API_AUDIENCE = #@TODO_REPLACE_WITH_YOUR_API_AUDIENCE

class AuthError(Exception):
    def __int__(self, error, status_code):
        self.error = error
        self.status_code = status_code

def get_token_auth_header():
    """Obtains the Access Token from the Authorization Header
    """
    auth = request.headers.get('Authorization', None)
    if not auth:
        raise AuthError({
            'code': 'authorization_header_missing',
            'description': 'Authorization header is expected.'
        }, 401)

    parts = auth.split()
    if parts[0].lower() != 'bearer':
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must start with "Bearer".'
        }, 401)

    elif len(parts) == 1:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Token not found.'
        }, 401)

    elif len(parts) > 2:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must be bearer token.'
        }, 401)

    token = parts[1]
    return token


def verify_decode_jwt(token):
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )

            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience and issuer.'
            }, 401)
        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)
    raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to find the appropriate key.'
            }, 400)


def get_token_auth_header():
    if 'Authorization' not in request.headers:
        abort(401)

    auth_headers = request.headers['Authorization']
    header_path = auth_headers.split(' ')

    if len(header_path) != 2:
        abort(401)

    elif header_path[0].lower() != 'bearer':
        abort(401)
    return header_path[1]

def check_permission(permission, payload):
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'Permisson not included in jwt'
         }, 400)
    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Permisson not found'
        }, 403)
    return True

def requires_auth(permission=''):
    def requires_auth_decoretor(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            try:
                payload = verify_decode_jwt(token)
            except:
                abort(401)
            
            check_permission(permission, payload)

            return f(payload, *args, **kwargs)
        return wrapper
    return requires_auth_decoretor

# @app.route('/headers')
# @requires_auth
# def headers(payload):
#     print(payload)
#     return 'Access Granted!'

@app.route('/images')
@requires_auth('get/images') #Add your custom permission by  creating Auth0
def images(jwt):
    print(jwt)
    return 'Permission granted!'

# @app.route('/')
# def index():
#     return f"<h1>Welcome to Index!!</h1>"


# if __name__ == '__main__':
#     app.run(use_debugger=False, use_reloader=False, passthrough_errors=True)

#Javascript to decode JWT:
# function parseJwt (token) {
#     // https://stackoverflow.com/questions/38552003/how-to-decode-jwt-token-in-javascript
#    var base64Url = token.split('.')[1];
#    var base64 = decodeURIComponent(atob(base64Url).split('').map((c)=>{
#        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
#    }).join(''));

#    return JSON.parse(base64);
# };
