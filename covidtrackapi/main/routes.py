from flask import Blueprint, request, jsonify
import json
from flask_login import login_required
from covidtrackapi.models import Notification, UserContact, UserInfo, User, Message, WorldUpdate, Role
from covidtrackapi import db
from covidtrackapi.users.utils import check_userdata, get_userqrcode, get_utc_time
from dateutil.parser import parse
from datetime import datetime
from  sqlalchemy import or_

main = Blueprint('main', __name__)

# Setting User public locations and Travel destinations
@main.route('/locale', methods=['PUT'])
# @roles_required('admin')
def user_locale():
    user_locale_data = request.get_json()

    required_locale_field = ["userid","localeType", "localeName"]

    check_userdata(user_locale_data, required_locale_field)

    user_id = user_locale_data['userid']
    localeType = user_locale_data['localeType']
    localeName = user_locale_data['localeName']

    userLoc = UserInfo.query.filter_by(userId=user_id).first()

    if not userLoc:
        response= {
        'status':'error',
        'message':'This User does not exist!'
        }

        return jsonify(response)

    offline_code = User.query.filter_by(userId=user_id).first().offlinecode

    if localeType == 'public':
        location_name = localeName
        public_qr = get_userqrcode(offline_code[0:6], contactType='public', contactLocation=location_name)
        userLoc.publicLocation = location_name
        userLoc.publicPlaceCode = public_qr

    else:
        travel_qr = get_userqrcode(offline_code[0:6], contactType='travel', contactLocation=localeName)
        userLoc.travelLocation = json.dumps(localeName)
        userLoc.travelCode = travel_qr

    try:
        db.session.commit()
        placesDB = userLoc.travelLocation
        if placesDB == None:
            placesDB = '{}'

        travelPlaces = json.loads(placesDB)

        response = {
        'status':'success',
        'message': f'{localeType} Successfully updated!',
        'data':{
            'public': userLoc.publicLocation ,
            'travel':travelPlaces,
            'publicPlaceCode': userLoc.publicPlaceCode ,
            'travelCode': userLoc.travelCode
            }
        }
        return jsonify(response)

    except Exception as e:
        response = {
        'status':'error',
        'message': f'Error Updating {localeType.capitalize()} Information! .'+str(e)
        }
        return jsonify(response)


@main.route('/message', methods=['POST'])
def send_message():

    if request.method == 'POST':
        user_message_data = request.get_json()

        required_message_field = ["sender","email", "subject", "message","messagedate"]

        check_userdata(user_message_data, required_message_field)

        user_id = user_message_data['sender']
        email = user_message_data['email']
        subject = user_message_data['subject']
        msg = user_message_data['message']
        msgdate = parse(user_message_data['messagedate'])

        user = User.query.filter_by(userId=user_id, email=email).first()

        if not user:
            response= {
            'status':'error',
            'message':'This User does not exist!'
            }

            return jsonify(response)

        message = Message(sender=user_id, subject=subject, msg=msg, senddate=msgdate, email=email)
        db.session.add(message)

        try:
            db.session.commit()

            response = {
            'status':'success',
            'message': f'Message Successfully Sent! We will get in touch with you as soon as possible.\n Thank you for reaching out to us!',
            }
            return jsonify(response)

        except Exception as e:
            response = {
            'status':'error',
            'message': f'Error Sending Message!.'+str(e)
            }
            return jsonify(response)
    else:
        messages = Message.query.all()

        response ={
        'status':'success',
        'message':'Messages Fetched Successfully',
        'data':[{'id':message.id,'sender':message.sender,'subject':message.subject, 'message':message.msg,'readstatus':message.readstatus, 'senddate':str(message.sentdate), 'email':message.email} for message in messages]
        }

        return jsonify(response)

@main.route('/manage_message', methods=['POST', 'PUT'])
def manage_message():
    user_message_data = request.get_json()
    required_message_field = ["userid","messageid", "sender"]
    if 'userid' not in user_message_data.keys():
        response = {
            'status':'error',
            'message':'Required data - userid not supplied!'
        }
        return jsonify(response)

    userid = user_message_data['userid']

    user = User.query.filter_by(userId=userid).first()

    if not user:
        response = {
            'status':'error',
            'message':f'User with user ID: {userid} is not available!'
        }
        return jsonify(response)

    userRole = Role.query.filter_by(id=int(user.roles)).first()

    if userRole.name != 'admin':
        response = {
            'status':'error',
            'message':'You are not an admin, You do not have the permission to perform this operation!'
        }
        return jsonify(response)

    if request.method == 'POST':

        messages = Message.query.all()
        received_messages = {}

        if len(messages) > 0:
            unread = 0
            for msg in messages:
                if msg.sender in received_messages.keys():
                    received_messages[msg.sender]['messages'].append({'messageid':msg.id, 'message':msg.msg, 'messagedate':msg.senddate, 'subject':msg.subject, 'status':msg.readstatus, 'email':msg.email})
                    if msg.readstatus == False:
                        received_messages[msg.sender]['unread'] += 1
                        msg.read_status=True
                        db.session.commit()

                else:
                    userDetails = User.query.filter_by(userId = msg.sender).first()
                    received_messages[msg.sender] = {'name':f'{userDetails.firstname} {userDetails.lastname}', 'messages':[{'messageid':msg.id, 'message':msg.msg, 'messagedate':msg.senddate, 'subject':msg.subject, 'status':msg.readstatus, 'email':msg.email}]}
                    received_messages[msg.sender]['unread'] = 0
                    if msg.readstatus == False:
                        received_messages[msg.sender]['unread'] = 1
                        msg.read_status=True
                        db.session.commit()
                    
                    

        response = {
        'status':'success',
        'message': f'Message Successfully Retrieved!',
        'data': received_messages
        }
        return jsonify(response)
    else:

        if 'messageid' not in user_message_data.keys():
            response = {
                'status':'error',
                'message':'Required data - messageid or sender missing!'
            }
            return jsonify(response)

        messageid = user_message_data['messageid']
        message = Message.query.filter_by(id=int(messageid)).first()

        if not message:
            response = {
                'status':'error',
                'message':f'No message with id {messageid} found!'
            }
            return jsonify(response)

        message.readstatus = True

        try:
            db.session.commit()
            response = {
                'status':'success',
                'message':'Message Successfully Read!',
                'data': message.id
            }
            return jsonify(response)

        except Exception as e:
            response = {
                'status':'error',
                'message':'Error Updating Message'
            }

            return jsonify(response)


@main.route('/covidupdates', methods=['POST'])
def get_all_covidupdates():
    user_message_data = request.get_json()

    required_message_field = ["country", "lastupdate"]

    check_userdata(user_message_data, required_message_field)

    country = user_message_data['country']
    latestupdatetime = parse(user_message_data['lastupdate']).replace(tzinfo=None)

    covid_updates = WorldUpdate.query.all()

    last_date_update = datetime.utcnow()

    if len(covid_updates) > 0:
        last_date_update = covid_updates[0].lastupdate

    update_data = [{'context': covid_update.context, 'data':json.loads(covid_update.data), 'lastupdate':covid_update.lastupdate} for covid_update in covid_updates]
    country_updates = {}
    continents_updates = {}
    my_country_data = {}

    if  latestupdatetime>last_date_update or last_date_update>latestupdatetime:
        for data in update_data:
            if data['context'] == 'country':
                country_updates = data
            else:
                continents_updates = data
        # Obtain data for a particular country
        for exact_data in country_updates['data']:
            if exact_data['country'] == country:
                my_country_data = exact_data
                break

        user_data = {
            'continent':continents_updates,
            'country':{
                'context':'country',
                'data': exact_data,
                'lastupdate':country_updates['lastupdate']
                }
        }

        response = {
        'status':'success',
        'message':'Updates fetched Successfully!',
        'data':user_data
        }

        return jsonify(response)
    else:
        response = {
        'status':'success',
        'message':'No new updates!'
        }
        return jsonify(response)


# ###############################################
#####            NOTIFICATIONS              #####
#################################################

@main.route('/notifications/<userid>', methods=['GET'])
# @login_required
# @token_required
def notification(userid):
    notifcations = Notification.query.filter_by(user_id=int(
        userid)).order_by(Notification.msg_date.desc()).all()

    message = 'You Currently Have No Notifications'
    data = []
    unread = 0

    if len(notifcations) > 0:
        user_notifications = [
            notification for notifcation in notifcations if notifcation.read_status == False]
        unread = len(user_notifications)
        message = 'User Notifications Successfully Fetched'
        data = [{'date': notification.msg_date, 'msg': notification.msg, 'read status': bool(
            notification.read_status), 'title': notification.title, 'sender': notification.sender} for notification in notifcations]

    response = {
        'status': 'success',
        'message': message,
        'count': unread,
        'data': data
    }
    return jsonify(response)


@main.route('/message', methods=['PUT'])
@login_required
def change_read_status():

    message_data = request.get_json()
    message_fields = ["message_id"]

    check_userdata(message_data, message_fields)

    message_id = int(message_data['message_id'])

    message = Message.query.filter_by(id=message_id).first()
    changed = False

    message = ''
    status = ''

    # Set the notofocation status as read if not already read
    if not message.readstatus:
        message.readstatus = True

        try:
            db.session.commit()
            changed = True
            status = 'success'
            message = 'Read Successfully'
        except Exception as e:
            status = 'error',
            message = 'Read Status Change Failed. '+str(e)

    response = {
        'status': status,
        'message': message,
        'data': changed
    }

    return jsonify(response)
