from flask import jsonify, request
from functools import wraps
from flask import current_app
from flask_login import current_user
from covidtrackapi.models import Role
import jwt, secrets, os, string, base64, io,json
from PIL import Image
from datetime import datetime
from covidtrackapi import app


def check_userdata(user_data, required_fields):
    if not user_data:
        response = {
            'status': 'error',
            "message": "Missing data"
        }

        return jsonify(response), 400

    if not all(field for field in required_fields):
        response = {
            'status': 'error',
            "message": "Required Fields Missing"
        }
        return jsonify(response), 400


# Define the user_roles decorator
def roles_required(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            count = 0
            for role in roles:
                if role in get_user_role():
                    count += 1

            if count == 0:
                response = {
                    'status': 'error',
                    'message': 'Roles required',
                    'error': 'You have inssufficient permisions'
                }
                return jsonify(response)
            return f(*args, **kwargs)
        return wrapped
    return wrapper


def get_user_role():
    user_roles = [role_id for role_id in list(current_user.roles)]
    all_roles = []
    for role in user_roles:
        all_roles.append(Role.query.filter_by(id=role).first().name)
    return all_roles

# Define the tokens decorator


def token_required(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            response = {
                'message': 'missing token',
                'status': 'error'
            }
            return jsonify(response), 403

        try:
            jwt.decode(token, app.config['SECRET_KEY'])
        except Exception as e:
            response = {
                'status': 'error',
                'message': 'Invalid or Expired Token. '+str(e)
            }
            return jsonify(response), 403
        return func(*args, **kwargs)
    return wrapped


def save_avartar(user_avartar):
    random_hex = secrets.token_hex(8)
    # _, img_ext = os.path.splitext(user_avartar.filename)
    img_ext = '.png'

    img_b64 = base64.b64decode(user_avartar)

    avartar_filename = random_hex + img_ext

    # Get full path where the image is to be saved
    avartar_path = os.path.join(
        current_app.root_path, 'static/avartar', avartar_filename)

    # Resize the image before saving
    img_output_size = (125, 125)
    buf = io.BytesIO(img_b64)
    img = Image.open(buf)
    img.thumbnail(img_output_size)

    img.save(avartar_path)
    return avartar_filename


def gen_usercode(code_len=6, password=False):
    pass_values = string.ascii_uppercase
    if password:
        pass_values = string.digits

    secrets.token_hex(16)[0:code_len]

    return ''.join(secrets.choice(pass_values) for _ in range(code_len))


def get_userqrcode(offcode, contactType='personal', contactLocation=[]):
    starting_char = '0000'
    ending_char = '1111'

    code_raw = json.dumps({'id':starting_char+offcode+ending_char, 'contacttype':contactType, 'contactlocation':contactLocation})

    # Encode the characters and
    code_encoded = code_raw.encode('utf-8')
    base_code = base64.b64encode(code_encoded)
    qr_url = 'wss://'+base_code.decode()
    return qr_url

def get_local_time(utc_time):
        # utc_time_date = datetime.strptime(utc_time, "%Y-%m-%d %H:%M")
        # utc_datetime_timestamp = float(utc_time_date.timestamp())
    utc_datetime_timestamp = float(utc_time.timestamp())

    return datetime.fromtimestamp(utc_datetime_timestamp)


def get_utc_time(local_time):
    # local_time_date = datetime.strptime(local_time, "%Y-%m-%d %H:%M")
    # local_datetime_timestamp = float(local_time_date.timestamp())
    local_datetime_timestamp = float(local_time.timestamp())

    return datetime.utcfromtimestamp(local_datetime_timestamp)
