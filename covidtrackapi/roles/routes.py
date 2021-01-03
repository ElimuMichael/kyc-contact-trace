# ###############################################
#####              USER ROLE                #####
#################################################
from flask import Blueprint, request, jsonify
from covidtrackapi import db
from covidtrackapi.models import Role, RoleApplication, User
from covidtrackapi.users.utils import check_userdata
from dateutil.parser import parse

roles = Blueprint('roles', __name__)


# Adding a new role
@roles.route('/roles', methods=['GET', 'POST'])
def role():

    if request.method == 'POST':
        new_role_data = request.get_json()
        new_role_fields = ["name", "description"]

        check_userdata(new_role_data, new_role_fields)

        role_name = new_role_data['name']
        description = new_role_data['description']

        role = Role.query.filter_by(name=role_name.lower()).first()
        if role:
            response = {
                'status': 'error',
                'message': 'User Role Already Exists'
            }
            return jsonify(response)

        else:
            new_role = Role(name=role_name.title(),
                            description=description)
            db.session.add(new_role)
            try:
                db.session.commit()
                response = {
                    'status': 'success',
                    'data': {'id':new_role.id, 'roleId': new_role.roleId, 'name':new_role.name, 'description': new_role.description},
                    'message': 'New Role Added Successfully'
                }
                return jsonify(response)
            except Exception as e:
                response = {
                    'status': 'error',
                    'message': 'Error Adding User Role. '+str(e)
                }
                return jsonify(response)
    else:
        roles = Role.query.all()

        message = 'There are currently no roles available'
        data = []

        if len(roles) > 0:
            message = 'Roles Fetched Successfully'
            data = [{'id': role.id, 'name': role.name.title(), 'description': role.description, 'roleId': role.roleId}
                    for role in roles]

        response = {
            'status': 'success',
            'message': message,
            'data': data
        }

        return jsonify(response)


# Delete an added role
@roles.route('/role/<int:role_id>/delete', methods=['DELETE'])
def del_role(role_id):
    role_item = Role.query.get_or_404(role_id)

    if role_item:
        db.session.delete(role_item)

        try:
            db.session.commit()

            response = {
                'status': 'success',
                'message': 'User Role Deleted Successfully'
            }
            return jsonify(response)

        except Exception as e:
            response = {
                'status': 'error',
                'message': 'Error Deleteing User Role ' + str(e)
            }
            return jsonify(response)

    else:
        response = {
            'status': 'error',
            'message': 'No such role found'
        }
        return jsonify(response)

# Updating the list of roles


@roles.route('/role/<int:role_id>/update', methods=['PUT'])
def update_role(role_id):

    updated_role_data = request.get_json()
    role_required_fields = ["name", "description"]
    check_userdata(updated_role_data, role_required_fields)

    role = Role.query.filter_by(id=role_id).first()

    if not role:
        response = {
            "status": "error",
            "message": "There is no Role with id {}".format(role_id)
        }

        return jsonify(response)

    if role.name == updated_role_data['name'] and role.description == updated_role_data['description']:
        response = {
            "status": "error",
            "message": "No Changes Made"
        }

        return jsonify(response)

    role.name = updated_role_data['name'].lower()
    role.description = updated_role_data['description']

    try:
        db.session.commit()

        response = {
            'status': 'success',
            'message': 'Role Updated Successfully'
        }
        return jsonify(response)

    except Exception as e:
        response = {
            'status': 'error',
            'message': 'Error Updating Role. ' + str(e)
        }
        return jsonify(response)



@roles.route('/user/role', methods=['PUT', 'POST'])
def update_user_role():

    user_role_data = request.get_json()
    role_application_fields = ["users", "description", "role_id"]
    check_userdata(user_role_data, role_application_fields)
    role_id = user_role_data['role_id']

    role = Role.query.filter_by(id=role_id).first()

    if not role:
        response = {
            "status": "error",
            "message": "There is no Role with id {}".format(role_id)
        }

        return jsonify(response)


    role.name = user_role_data['name'].lower()
    role.description = user_role_data['description']

    try:
        db.session.commit()

        response = {
            'status': 'success',
            'message': 'Role Updated Successfully'
        }
        return jsonify(response)

    except Exception as e:
        response = {
            'status': 'error',
            'message': 'Error Updating Role. ' + str(e)
        }
        return jsonify(response)

@roles.route('/apply', methods=['POST'])
def apply_for_role():

    user_data = request.get_json()

    user_fields = ["sender", "email", "organizationType", "organizationName", "reason", "organizationRole", "applicationDate"]

    check_userdata(user_data, user_fields)

    senderId = user_data['sender']
    email = user_data['email']
    organizationName = user_data['organizationName']
    organizationType= user_data['organizationType']
    organizationRole = user_data['organizationRole']
    applicationReason = user_data['reason']
    applicationDate = parse(user_data['applicationDate'])

    role = Role.query.filter_by(name='supervisor').first()

    application = RoleApplication(sender=senderId, email=email, roleId=role.roleId, organization_role=organizationRole, organization_type=organizationType, organization_name=organizationName, reason=applicationReason, application_date=applicationDate)
    db.session.add(application)

    try:
        db.session.commit()
        response = {
            'status': 'success',
            'message': 'Application Successfully Submitted',
            'data': {'id': application.id, 'organizationName':organizationName, 'reason': applicationReason, 'organizationType':organizationType, 'organizationRole':organizationRole, 'applicationDate':application.application_date, 'status': application.application_status}
        }

        return jsonify(response)
    except Exception as e:

        response = {
            'status': 'error',
            'message': 'Error Submitting application. '+str(e),
        }

        return jsonify(response)

@roles.route('/my_application', methods=['POST'])
def track_my_application():

    user_data = request.get_json()

    user_fields = ["userid"]

    check_userdata(user_data, user_fields)

    senderId = user_data['userid']

    application = RoleApplication.query.filter_by(sender=senderId).first()

    data = {}
    if application:
        data = {'id': application.id, 'reason':application.reason,  'organizationName':application.organization_name, 'organizationType':application.organization_type, 'organizationRole':application.organization_role, 'applicationDate':application.application_date, 'status': application.application_status}
    

    response = {
        'status': 'success',
        'message': 'Application Successfully Fetched',
        'data': data
    }

    return jsonify(response)


@roles.route('/applications', methods=['POST', 'PUT'])
def manage_user_applications():

    user_data = request.get_json()
    user_fields = ["userid", "applicationid", "action"]

    if 'userid' not in user_data.keys():
        response = {
            'status': 'error',
            'message': 'Missing required field - userid'
        }
        return jsonify(response)

    userid = user_data['userid']
    user = User.query.filter_by(userId=userid).first()

    if not user:
        response = {
            'status':'error',
            'message': 'user does not Exists!',
        }
        return jsonify(response)


    userrole = Role.query.filter_by(id=int(user.roles)).first()

    if userrole.name != 'admin':
        response = {
            'status':'error',
            'message': 'You do not have the permission to view user applications!',
        }
        return jsonify(response)


    if request.method == 'POST':

        applications = RoleApplication.query.all()

        data = []

        if len(applications) > 0:
            data = [{'id': application.id, 'reason':application.reason,  'organizationName':application.organization_name, 'organizationType':application.organization_type, 'organizationRole':application.organization_role, 'applicationDate':str(application.application_date), 'status': application.application_status} for application in applications]
            
        response = {
            'status': 'success',
            'message': 'Applications Fetched successfully!',
            'data': data
            }

        return jsonify(response)
        
    else:
        if ('applicationid' not in user_data.keys()) or ('action' not in user_data.keys()):
            response = {
                'status':'error',
                'message': 'Missing required field - applicationid and/or action'
            }
            return jsonify(response)

        applicationid = user_data['applicationid']
        action = user_data['action']

        application = RoleApplication.query.filter_by(id=int(applicationid)).first()

        if not application:
            response = {
                'status':'error',
                'message': f'No application with id={applicationid}'
            }

            return jsonify(response)

        user = User.query.filter_by(userId=application.sender).first()
        if action == 'accept':
            application.application_status = 'Approved'
            role = Role.query.filter_by(roleId=application.roleId).first()

            user.roles = str(role.id)
        elif action=='reject':
            application.application_status = 'Rejected'
        
        elif action == 'revoke':
            application.application_status = 'Revoked'

            role = Role.query.filter_by(name='user').first()
            user.roles = str(role.id)
        
        try:
            db.session.commit()
            response = {
                'status': 'success',
                'message': 'Role Updated Successfully',
            }

            print(f'Response: {response}')

            return jsonify(response)

        except Exception as e:
            response = {
                'status': 'error',
                'message': 'Error Updating Application. '+str(e),
            }

            print(f'Response: {response}')

            return jsonify(response)