# ###############################################
#####                LOGIN                  #####
#################################################
from flask import Blueprint, render_template, request, flash, redirect, url_for, json, current_app, jsonify
import jwt, random, os
from datetime import datetime, timedelta, date
from covidtrackapi.users.utils import save_avartar, get_user_role, get_local_time, gen_usercode, token_required, get_userqrcode, check_userdata
from flask_login import login_user, logout_user, current_user, login_required
from covidtrackapi.models import  User, Role, UserInfo, Notification, UserContact
from dateutil.parser import parse

from covidtrackapi import app, db, bcrypt, mail, socketio
from flask_socketio import send, join_room, leave_room, rooms
from flask_mail import Message
global online_users
online_users = {}
global messages
messages = {}

users = Blueprint('users', __name__)

@users.route('/register', methods=['POST'])
def register():
    user_reg_data = request.get_json()
    required_reg_fields = ["phone", "password", "firstname", "lastname", "email", "country", "state", "street", "avartar"]
    
    check_userdata(user_reg_data, required_reg_fields)

    phone = user_reg_data['phone']
    email = user_reg_data['email']
    password = user_reg_data['password']
    firstname = user_reg_data['firstname']
    lastname = user_reg_data['lastname']
    country = user_reg_data['country']
    state = user_reg_data['state']
    street = user_reg_data['street']
    avartar = user_reg_data['avartar']
    avartar_file = save_avartar(avartar)

    user = User.query.filter_by(phone=phone).first()

    if user:
        response = {
        'status':'error',
        'message':'User already exists!'
        }
        return jsonify(response)
    role = 'user'
    if phone == '+256779200330' and firstname=='Michael' and lastname=='Elimu':
        role = 'admin'

    user_role = Role.query.filter_by(name=role).first()

    pass_hashed = bcrypt.generate_password_hash(password).decode('utf-8')
    offlinecode = gen_usercode()
    offlinepassword = gen_usercode(code_len=5, password=True)
    hashedofflinepwd = bcrypt.generate_password_hash(offlinepassword).decode('utf-8')

    usercode = get_userqrcode(offlinecode, contactType='personal')

    user = User(phone=phone, password=pass_hashed, roles=str(user_role.id), firstname=firstname, lastname=lastname, email=email, usercode=usercode, offlinecode=f'{offlinecode}-{offlinepassword}', offlinepassword=hashedofflinepwd, avartar=avartar_file)
    db.session.add(user)
    try:
        db.session.commit()

        token = jwt.encode({
            'user': user.id,
            'exp': get_local_time(datetime.utcnow()) + timedelta(days=30)
        }, app.config['SECRET_KEY'])

        init_loc = {}

        add_info = UserInfo(userId=user.userId, country=country, street=street, state=state, travelLocation=json.dumps(init_loc))
        notification_data = {}
        user_notification = Notification(usercode=offlinecode[:6], data=json.dumps(notification_data))
        db.session.add_all((add_info, user_notification))
        url = request.host_url

        db.session.commit()

        response = {
            'status': 'success',
            'message': 'Account Created Successfully!',
            'token': token.decode('utf-8'),
            'id': user.id,
            'userId': user.userId,
            'firstname': firstname,
            'lastname': lastname,
            'email': email,
            'phone': phone,
            'role': user_role.name,
            'country': country,
            'offlinecode': offlinecode+'-'+offlinepassword,
            'findme': False,
            'infected': False,
            'recovered': False,
            'infectiondate': user.infection_date,
            'recoverydate': user.recovery_date,
            'publicLocation': add_info.publicLocation,
            'travelLocations': add_info.travelLocation,
            'publicPlaceCode': add_info.publicPlaceCode,
            'vaccinated': add_info.vaccinated,
            'vacRef': add_info.vacRef,
            'travelCode': add_info.travelCode,
            'socialdistance': 2,
            'usercode': usercode,
            'avartar': url+'/static/avartar/'+avartar_file
        }
        return jsonify(response)
    except Exception as e:
        response = {
            'status': 'error',
            'message': 'Error Creating User. '+str(e)
        }
        return jsonify(response)

@users.route('/checkphone', methods=['POST'])
def check_userphone():
    user_login_data = request.get_json()
    required_login_fields = ["phone"]
    check_userdata(user_login_data, required_login_fields)

    user = User.query.filter_by(phone=user_login_data['phone']).first()

    if user:
        response = {
            'status': 'success',
            'exists': True
        }
        return jsonify(response)
    else:
        response = {
            'status': 'success',
            'exists': False
        }
        return jsonify(response)

@users.route('/checkuser', methods=['POST'])
def check_user_existance():
    user_check_data = request.get_json()
    required_check_fields = ["usercode"]
    check_userdata(user_check_data, required_check_fields)
    user_code = user_check_data["usercode"].upper()

    user_offlinecode, user_offlinepwd = user_code.split('-')

    user = User.query.filter_by(offlinecode=user_code).first()

    if user:
        if bcrypt.check_password_hash(user.offlinepassword, user_offlinepwd):
            travel_details = UserInfo.query.filter_by(userId=user.userId).first()
            response = {
                'status': 'success',
                'message': 'Valid Details',
                'data': {'travelLocations':travel_details.travelLocation, 'publicLocation':travel_details.publicLocation}
            }
            return jsonify(response)
        else:
            response = {
                'status': 'error',
                'message': 'Invalid Second Code'
            }
            return jsonify(response)
    else:
        response = {
            'status': 'error',
            'message': 'Invalid First Code'
        }
        return jsonify(response)

@users.route('/')
@users.route('/index')
@users.route('/login', methods=['POST'])
def login():
    user_login_data = request.get_json()
    required_login_fields = ["phone", "password"]
    check_userdata(user_login_data, required_login_fields)

    user = User.query.filter_by(phone=user_login_data['phone']).first()

    if user:
        if bcrypt.check_password_hash(user.password, user_login_data['password']):
            # login_user(user)
            user_role = Role.query.filter_by(id=int(user.roles)).first().name

            token = jwt.encode({
                'user': user.id,
                'exp': get_local_time(datetime.utcnow()) + timedelta(days=30)
            }, app.config['SECRET_KEY'])

            add_info = UserInfo.query.filter_by(userId=user.userId).first()
            url = request.host_url

            response = {
                'status': 'success',
                'message': 'Login Successful',
                'token': token.decode('utf-8'),
                'userId': user.userId,
                'id': user.id,
                'infected': user.isinfected,
                'recovered': user.recovered,
                'infectiondate': user.infection_date,
                'recoverydate': user.recovery_date,
                'firstname': user.firstname,
                'lastname': user.lastname,
                'email': user.email,
                'role': user_role,
                'offlinecode': user.offlinecode,
                'country':add_info.country,
                'findme': add_info.findme,
                'vaccinated': add_info.vaccinated,
                'vacRef': add_info.vacRef,
                'socialdistance': add_info.socialdistance,
                'publicLocation': add_info.publicLocation,
                'publicPlaceCode': add_info.publicPlaceCode,
                'travelLocation': add_info.travelLocation,
                'travelCode': add_info.travelCode,
                'usercode': user.usercode,
                'avartar': url+'/static/avartar/'+user.avartar
            }
            return jsonify(response)
        else:
            response = {
                'status': 'error',
                'message': 'Invalid Password'
            }
            return jsonify(response)
    else:
        response = {
            'status': 'error',
            'message': f'No user with phone number {user_login_data["phone"]}. Please Register or Check your Login credentials'
        }
        return jsonify(response)


@users.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    response = {
        'status': 'success',
        'message': 'Log out successful'
    }
    return jsonify(response)


# ###############################################
#####               PROFILE                 #####
#################################################


@users.route('/profile/<userid>', methods=['GET', 'PUT'])
# @token_required
# @login_required
def profile(userid):

    current_user = User.query.filter_by(userId=userid).first()
    if not current_user:
        response = {
            'status': 'error',
            'message': 'No such user in the system'
        }
        return jsonify(response)

    if request.method == 'PUT':
        user_data = request.get_json()
        required_fields = ["firstname", 'lastname',
                           'email', 'avartar', 'searchable', 'socialdistance']

        if not user_data:
            response = {
                'status': 'error',
                "message": "Missing data"
            }
            return jsonify(response)

        if current_user:
            if 'findme' in user_data.keys():
                current_user.findme = user_data['findme']
            if 'firstname' in user_data.keys():
                current_user.firstname = user_data['firstname']
            if 'lastname' in user_data.keys():
                current_user.lastname = user_data['lastname']
            if 'email' in user_data.keys():
                current_user.email = user_data['email']
            if 'avartar' in user_data.keys():
                avartar_file = save_avartar(user_data['avartar'])

                # Get previous user avatar and delete it
                if current_user.avartar != 'person.jpg':
                    old_avartar_path = os.path.join(
                        current_app.root_path, 'static/avartar', current_user.avartar)
                    os.remove(f'{old_avartar_path}')

                current_user.avartar = avartar_file

            try:
                db.session.commit()
                avartar_url = url_for(
                    'static', filename=f'avartar/{current_user.avartar}')
                response = {
                    'status': 'success',
                    'message': 'Your Profile has been updated',
                    'data': {'id': current_user.id, 'email': current_user.email, 'firstname': current_user.firstname, 'lastname': current_user.lastname, 'avartar': avartar_url}
                }

                return jsonify(response)

            except Exception as e:
                response = {
                    'status': 'error',
                    'message': 'Profile Update Failed'
                }
                return jsonify(response)

        else:
            response = {
                'status': 'error',
                'message': f"Error Fetching User with id={user_data['userid']}"
            }
            return jsonify(response)
    else:
        avartar_url = url_for(
            'static', filename=f'avartar/{current_user.avartar}')
        response = {
            'status': 'success',
            'message': 'Profile Fetched Successfully',
            'data': {'id': current_user.id, 'userId': current_user.userId, 'email': current_user.email, 'firstname': current_user.firstname, 'lastname': current_user.lastname, 'avartar': avartar_url, 'phone': current_user.phone}
        }

        return jsonify(response)

@users.route('/reset_token', methods=['POST'])
def reset_request():
    user_reset_data = request.get_json()
    required_reset_fields = ["email", 'phone']
    
    check_userdata(user_reset_data, required_reset_fields)
    email=user_reset_data['email']
    phone = user_reset_data['phone']
    print(user_reset_data)

    user = User.query.filter_by(phone=phone).first()

    if user:
        print(user.email)
        if user.email==email:
            reset_token = user.get_reset_token()

            response = {
                'status': 'success',
                'message': 'Reset Token Generated Successfully.',
                'reset_token':reset_token
            }
            return jsonify(response)
        else:
            response = {
                'status': 'error',
                'message': 'Invalid Email Address Provided!'
            }
            return jsonify(response)
    else:
        response = {
            'status': 'error',
            'message': 'Invalid Phone Number Provided!'
        }
        return jsonify(response)


@users.route('/reset_password', methods=['POST'])
def reset_password():
    user_data = request.get_json()
    if not user_data:
        response = {
            'status': 'error',
            'message': 'Missing Data'
        }
        return jsonify(response)

    if 'reset_token' not in user_data.keys():
        response = {
            'status': 'error',
            'message': 'Missing Token'
        }
        return jsonify(response)
    if 'password' not in user_data.keys():
        response = {
            'status': 'error',
            'message': 'Input New Password'
        }
        return jsonify(response)

    resettoken = user_data['reset_token']

    user = User.verify_reset_token(resettoken)
    if user is None:
        response = {
            'status': 'error',
            'message': 'An invalid or Expired Token'
        }

        return jsonify(response)

    if 'old_password' in user_data.keys():
        old_password = user_data['old_password']
        if not bcrypt.check_password_hash(user.password, old_password):
            response = {
                'status': 'error',
                'message': 'Invalid Old Password.'
                }
            return jsonify(response)

    hashed_password = bcrypt.generate_password_hash(user_data['password'])
    user.password = hashed_password
    try:
        db.session.commit()
        response = {
            'status': 'success',
            'message': 'Your password has successfully been updated.'
        }

        return jsonify(response)
    except Exception as e:
        response = {
            'status': 'error',
            'message': 'Error Changing Password'
        }

        return jsonify(response)

@users.route('/users', methods=['POST'])
def get_kyc_users():
    print('here in kyc users')
    request_data = request.get_json()
    required_request_fields = ["userid", "countrycode"]
    check_userdata(request_data, required_request_fields)
    userId = request_data['userid']
    countrycode = request_data['countrycode']

    user = User.query.filter_by(userId=userId).first()
    if user:
        user_role = Role.query.filter_by(id=int(user.roles)).first()
        if user_role.name =='admin':
            users = User.query.filter(user.phone.startswith(countrycode)).all()

            print([user.firstname for user in users])

            response = {
                'status': 'success',
                'message': 'Users Fetched Successful',
                'data':[{'userId':user.userId, 'offlinecode':user.offlinecode[0:6], 'nin':user.nin, 'phone':user.phone, 'infected':user.isinfected, 'recovered':user.recovered, 'recoverydate':user.recovery_date, 'infectiondate':user.infection_date} for user in users if user.userId != userId]
                
            }
            return jsonify(response)
        else:
            response = {
                'status': 'error',
                'message': 'You do not have the right to see all users'
            }
            return jsonify(response)
    else:
        response = {
            'status': 'error',
            'message': f'No user with id {userId}'
        }
        return jsonify(response)



@users.route('/findme', methods=['POST'])
def change_findme_status():
    request_data = request.get_json()
    required_request_fields = ["userid", "lat", 'lng', 'findme', 'country']
    check_userdata(request_data, required_request_fields)
    userId = request_data['userid']
    lat = request_data['lat']
    lng = request_data['lng']
    findme = request_data['findme']
    usercode = request_data['usercode']
    country = request_data['country']
    user = UserInfo.query.filter_by(userId=userId).first()
    if user:
        user.findme = findme
        user.lat = lat
        user.lng = lng
        try:
            db.session.commit()
            response = {
                'status': 'success',
                'message': 'Users Finding Changed',
                'data':{'userId':userId, 'usercode':usercode, 'lat':lat, 'lng':lng, 'country':country, 'findme':findme}
            }
            return jsonify(response)
        except Exception as e:
            response = {
                'status': 'error',
                'message': 'Error Updating Find me status. '+str(e)
            }
            return jsonify(response)
    else:
        response = {
            'status': 'error',
            'message': f'No user with id {userId}'
        }
        return jsonify(response)


@socketio.on('connect')
def connect():
    user_data = request.args
    user = {
    'usercode': user_data.get('from'),
    'country':user_data.get('country'),
    # 'lat': user_data.get('lat'),
    # 'lng': user_data.get('lng'),
    'findme': user_data.get('findme')=='true'
    }
    # required_conn_fields = ["token", "country", "userId"]
    # check_userdata(data, required_conn_fields)
    # token = data['token']
    # country = data['country']
    # userid = data['userId']4
    # lat = data['lat']
    # lng = data['lng']
    if user['country'] not in online_users.keys():
        online_users.update({user['country']:{user['usercode']:{'sessionid':request.sid,'findme': user['findme']}}})
    elif user['usercode'] not in online_users[user['country']]:
        online_users[user['country']].update({user['usercode']:{'sessionid':request.sid,'findme': user['findme']}})
    else:
        online_users[user['country']][user['usercode']].update({'sessionid':request.sid})
    
    socketio.emit('user_connected', {'data': f'Hello {user["usercode"]}'})
    print(online_users)

def messageReceived(methods=['GET', 'POST']):
    pass

@socketio.on('disconnect')
def  disconnect():
    user_data = request.args

    usercode= user_data.get('from')
    country=user_data.get('country')
    if usercode in online_users[country].keys():
        online_users[country].__delitem__(usercode)

@socketio.on('message')
def  message(data):
    print(f'\n\n{data}\n\n')

    send(data)


# @socketio.on('join')
# def  join_room(data):
#     if 'country' in data.keys():
#         country = data['country']
#         usercode = data['usercode']
#         room = online_users[country][usercode]
#         join_room(room)
#         send(data)


# @socketio.on('leave')
# def  leave_room(data):
#     print(f'\n\n{data}\n\n')
#     send(data)


@socketio.on('user_updates')
def handle_get_updates_event(data):
    usercode = data['usercode']
    country = data['country']
    countrycode = data['countrycode']
    sess_id = online_users[country][usercode]

    # user_notificcations = Notification.query.filter_by(usercode=usercode).first()
    # data_json = json.loads(user_notificcations['data'])
    uploads = data['uploads']
    infectedUserConacts = data['infected']
    updates = []
    downloads = []
    allInfected = []
    usercontacts = []

    userContactsUndownloaded = UserContact.query.filter_by(client2=usercode, downloaded=False).all()

    if len(infectedUserConacts) > 0:
        for user_contact in infectedUserConacts:
            user = User.query.filter(User.offlinecode.startswith(user_contact)).first()
            if not user.isinfected:
                usercontacts = UserContact.query.filter_by(client1=user_contact).all() + UserContact.query.filter_by(client2=user_contact).all()
                for contact in usercontacts:
                    allInfected.append({'contactcode':contact.contactcode, 'infected':False})

    for contact in userContactsUndownloaded:
        contact.downloaded = True
        try:
            db.session.commit()
        except Exception as e:
            print('Exception Occured '+ str(e))
    
    downloads = [{'client1':contact.client1, 'client2':contact.client2, 'contactcode':contact.contactcode, 'contacttype': contact.contacttype, 'pickuptime': str(contact.contacttime), 'source':contact.source, 'destination':contact.destination, "uploaded":True, 'infected': contact.infected} for contact in userContactsUndownloaded]

    if len(uploads) > 0:
        for contact in uploads:
            to_id = contact['client2']

            contactcode = contact['contactcode'] 
            client1 = contact['client1'] 
            client2 = contact['client2']
            contacttime = parse(contact['pickuptime'])
            contacttype = contact['contacttype'] 
            source = contact['source'] 
            infected = contact['infected']
            destination = contact['destination']
            sess_id = ''            
            if to_id in online_users[country].keys():
                sess_id = online_users[country][to_id]
                dowloaded = True

            else:
                dowloaded = False

            user_contact = UserContact(contactcode=contactcode, client1=client1, client2=client2, contacttime=contacttime, contacttype=contacttype, source=source, destination=destination, downloaded=dowloaded,infected=infected)
            db.session.add(user_contact)
            try:
                db.session.commit()
                updates.append(contactcode)
                if sess_id is not '':
                    socketio.emit('notify_users', data, room=sess_id['sessionid'])
            except:
                continue

    # Check if any of the users among contacts is infected

    infectedCountryUsers = User.query.filter(User.phone.startswith(countrycode), User.isinfected).all()
    usersInfected = [user.offlinecode.split('-')[0] for user in infectedCountryUsers]

    if len(usersInfected) > 0:
        for user in usersInfected:
            usercontacts = UserContact.query.filter_by(client1=usercode, client2=user).all() + UserContact.query.filter_by(client1=user, client2=usercode).all()
            for contact in usercontacts:
                if (contact.client1 in infectedUserConacts) or (contact.client2 in infectedUserConacts):
                    continue
                else:
                    allInfected.append({'contactcode':contact.contactcode, 'infected':True})

    sess_id = online_users[country][usercode]
    data = {'updates':updates,'downloads':downloads, 'infected': allInfected}
    socketio.emit('update_received', data, room=sess_id['sessionid'])


@socketio.on('send_notification')
def handle_notification_event(contactData):
    print('Sending Notification')
    to_id = contactData['data']['client2']
    country =contactData['country']
    if to_id in online_users[country].keys():
        sess_id = online_users[country][to_id]
        print(f'User  online. Session Id: {sess_id}')
        socketio.emit('notify_users', contactData, to=sess_id['sessionid'])


@socketio.on('set_findme')
def handle_setfindme_event(data):
    user_offlinecode = data['usercode']
    country = data['country']
    findme = data['findme']
    if user_offlinecode in online_users[country].keys():
        online_users[country][user_offlinecode].update({'findme': findme})

@socketio.on('get_close_users')
def find_closeusers_event(data):
    user_offlinecode = data['usercode']
    country = data['country']
    user_lat = data['lat']
    user_lng = data['lng']
    if user_offlinecode in online_users[country].keys():
        user = online_users[country][user_offlinecode]

        locationData = {
            'usercode': user_offlinecode,
            'country':country,
            'lat': user_lat,
            'lng': user_lng
        }

        for other_user in online_users[country]:
            if other_user != user_offlinecode:
                user = online_users[country][other_user]
                if user['findme']:
                    socketio.emit('check_proximity', locationData, to=user['sessionid'])

@socketio.on('within_proximity')
def users_within_proximity(data):
    user_offlinecode = data['usercode']
    country = data['country']

    if user_offlinecode in online_users[country].keys():
        user = online_users[country][user_offlinecode]

        nearUsers = {
            'client1': user_offlinecode,
            'client2': data['client2'],
            'distance': data['distance']
        }
        socketio.emit('fitting_proximity', nearUsers, to=user['sessionid'])



