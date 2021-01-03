# ###############################################
#####                LOGIN                  #####
#################################################
from flask import Blueprint, render_template, request, flash, redirect, url_for, json, current_app, jsonify
import jwt
from datetime import datetime, timedelta, date
from dateutil.parser import parse
from covidtrackapi.users.utils import save_avartar, get_user_role, get_local_time, gen_usercode, token_required, get_userqrcode, check_userdata
from flask_login import login_user, logout_user, current_user, login_required
import random, os
from covidtrackapi.models import  User, UserContact, UserInfo, Role

from covidtrackapi import app, db, bcrypt, mail
from flask_mail import Message

contacts = Blueprint('contacts', __name__)

@contacts.route('/upload', methods=['POST'])
def upload():
    user_reg_data = request.get_json()
    required_reg_fields = ["data"]
    
    check_userdata(user_reg_data, required_reg_fields)

    data = user_reg_data['data']
    userId = user_reg_data['data']['userId']

    user = User.query.filter_by(userId=userId).first()

    if not user:
        response = {
        'status':'error',
        'message':'User does not exists!'
        }
        return jsonify(response)

    contactcode = data['contactcode'] 
    client1 = data['client1'] 
    client2 = data['client2'].split('-')[0]
    contacttime = parse(data['pickuptime'])
    contacttype = data['contacttype'] 
    source = data['source'] 
    dowloaded = data['uploaded'] 
    infected = data['infected']

    destination = ''

    if 'destination' in data.keys():
        destination = data['destination'] 

    user_contact = UserContact(contactcode=contactcode, client1=client1, client2=client2, contacttime=contacttime, contacttype=contacttype, source=source, destination=destination, downloaded=dowloaded,infected=infected)
    
    db.session.add(user_contact)
    try:
        db.session.commit()
        response = {
            'status': 'success',
            'message': 'Contact Added Successfully!',
        }
        return jsonify(response)
    except Exception as e:
        response = {
            'status': 'error',
            'message': 'Error Adding Contact. '+str(e)
        }
        return jsonify(response)


@contacts.route('/changestatus', methods=['PUT'])
def change_user_status():
    user_update_data = request.get_json()
    required_update_fields = ["data", "usertype", "userid"]
    
    check_userdata(user_update_data, required_update_fields)

    data = user_update_data['data']
    action = user_update_data['usertype']
    userId = user_update_data['userid']

    user = User.query.filter_by(userId=userId).first()

    if not user:
        response = {
        'status':'error',
        'message':'User does not exists!'
        }
        return jsonify(response)

    role_name = ''

    userrole = Role.query.filter_by(id=int(user.id)).first()
    if userrole:
        role_name = userrole.name

    if role_name != 'admin':
        response = {
            'status':'error',
            'message':'You do not have the right to perform this operation!'
            }
        return jsonify(response)

    updatedUsers = []
    updatetime = datetime.utcnow()

    for usercode in data:
        particularUser = User.query.filter_by(userId=usercode).first()        
        if action == 'Uninfected':
            particularUser.isinfected = True
            particularUser.infection_date = updatetime
        elif action == 'Infected':
            particularUser.isinfected = False
            particularUser.recovered = True
            particularUser.recovery_date = updatetime
        elif action == 'Recovered':
            particularUser.isinfected = True
            particularUser.recovered = False

        try:
            db.session.commit()
            updatedUsers.append(usercode)

        except Exception as e:
                continue

    response = {
        'status': 'success',
        'message': 'Contact Updated Successfully!',
        'data':updatedUsers
    }
    return jsonify(response)


@contacts.route('/likely_infected', methods=['POST'])
def likely_infected_users():
    user_data = request.get_json()
    required_fields = ["infecteduser", "userId"]
    
    check_userdata(user_data, required_fields)

    infecteduser = user_data['infecteduser']
    userId = user_data['userId']
    data = {}

    user = User.query.filter_by(userId=userId).first()

    if not user:
        response = {
            'status':'error',
            'message':'User does not exists!'
        }
        return jsonify(response)

    userrole = Role.query.filter_by(id=int(user.id)).first().name

    if userrole != 'admin':
        response = {
            'status':'error',
            'message':'You do not have the right to perform this operation!'
            }
        return jsonify(response)

    likely_infected_users = {}
    user_contacts = UserContact.query.filter((UserContact.client1==infecteduser)|(UserContact.client2==infecteduser)).all()
    if len(user_contacts)> 0:
        for user in user_contacts:
            if user.client1 == infecteduser:
                if user.client2 in data.keys():
                    data[user.client2].append({'contactcode':user.contactcode, 'source':user.source, 'destination':user.destination, 'contacttime': user.contacttime, 'contacttype':user.contacttype})
                else:
                    data[user.client2]=[{'contactcode':user.contactcode, 'source':user.source, 'destination':user.destination, 'contacttime': user.contacttime, 'contacttype':user.contacttype}]
            else:
                if user.client1 in data.keys():
                    data[user.client1].append({'contactcode':user.contactcode, 'source':user.source, 'destination':user.destination, 'contacttime': user.contacttime, 'contacttype':user.contacttype})
                else:
                    data[user.client1]=[{'contactcode':user.contactcode, 'source':user.source, 'destination':user.destination, 'contacttime': user.contacttime, 'contacttype':user.contacttype}]
    response = {
        'status': 'success',
        'message': 'Previous Contact Fetched Successfully!',
        'data': data
    }
    return jsonify(response)


@contacts.route('/update', methods=['POST'])
def fetch_updates():
    user_data = request.get_json()
    required_fields = ["offlinecode"]
    check_userdata(user_data, required_login_fields)
    user_code = user_data['offlinecode'].split('-')[0]

    user_updates = UserContact.query.filter_by(client2=user_code, downloaded=False).all()

    if user_updates.length>0:
        
        response = {
            'status': 'success',
            'message': 'New Updates Fetched',
            'data': user_updates
        }
        return jsonify(response)
    else:
        response = {
            'status': 'success',
            'message': 'No updates'
        }
        return jsonify(response)

