from covidtrackapi import db, loginmanager, app
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_login import UserMixin
import uuid
from datetime import datetime

def generate_key():
    random_key = uuid.uuid4().urn
    gen_key = random_key[9:]

    return gen_key

@loginmanager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.String, unique=True,
                       nullable=False, default=generate_key)
    phone = db.Column(db.String, unique=True, nullable=False)
    firstname = db.Column(db.String(30))
    lastname = db.Column(db.String(30))
    email = db.Column(db.String(120))
    nin = db.Column(db.String(120))
    roles = db.Column(db.String, nullable=False)
    offlinecode = db.Column(db.String, nullable=False)
    offlinepassword = db.Column(db.String, nullable=False)
    usercode = db.Column(db.String, nullable=False)
    avartar = db.Column(db.String, default='person.jpg', nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=1)
    recovered = db.Column(db.Boolean, nullable=False, default=0)
    isinfected = db.Column(db.Boolean, nullable=False, default=0)
    infection_date = db.Column(db.DateTime)
    recovery_date = db.Column(db.DateTime)
    account_status = db.Column(db.Boolean, nullable=False, default=1)

    def get_reset_token(self, expires_sec=1800):
        serial = Serializer(app.config['SECRET_KEY'], expires_sec)
        return serial.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        serial = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = serial.loads(token)['user_id']
        except Exception:
            return None

        return User.query.get(user_id)

    def __repr__(self):
        return f"""User('{self.id}', '{self.usercode}', '{self.offlinecode}','{self.offlinepassword}', '{self.userId}','{self.phone}',
        '{self.firstname}','{self.lastname}', '{self.email}', '{self.avartar}', '{self.roles}', '{self.is_active}', '{self.isinfected}',
        '{self.is_active}', '{self.infection_date}','{self.recovery_date}')"""


class UserInfo(db.Model):
    __tablename__ = 'user_info'
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.String, db.ForeignKey('user.userId', ondelete='CASCADE'), unique=True, nullable=False)
    country = db.Column(db.String(11), nullable=False)
    state = db.Column(db.String(30))
    street = db.Column(db.String(30))
    lat = db.Column(db.String(30))
    lng = db.Column(db.String(30))
    publicLocation = db.Column(db.String(30))
    travelLocation = db.Column(db.String)
    publicPlaceCode = db.Column(db.String)
    travelCode = db.Column(db.String)
    findme = db.Column(db.Boolean, nullable=False, default=0)
    socialdistance = db.Column(db.Integer, nullable=False, default=2)
    vaccinated = db.Column(db.Boolean, nullable=False, default=0)
    vacRef = db.Column(db.String)

    def __repr__(self):
        return f"""UserInfo('{self.id}', '{self.userId}','{self.findme}','{self.socialdistance}','{self.country}','{self.state}',
        '{self.street}','{self.lat}','{self.lng}','{self.publicLocation}','{self.travelLocation}','{self.travelCode}','{self.publicPlaceCode}'
        ,'{self.vaccinated}','{self.vacRef}')"""


class UserContact(db.Model):
    __tablename__ = 'user_contact'
    id = db.Column(db.Integer, primary_key=True)
    contactcode = db.Column(db.String, unique=True, nullable=False)
    client1 = db.Column(db.String, nullable=False)
    client2 = db.Column(db.String, nullable=False)
    contacttime = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    contacttype = db.Column(db.String, nullable=False)
    source = db.Column(db.String, nullable=False)
    destination = db.Column(db.String)
    downloaded = db.Column(db.Boolean, nullable=False, default=False)
    infected = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f"""UserContact('{self.id}','{self.contactcode}','{self.client1}','{self.client2}', '{self.contacttime}', 
        '{self.source}', '{self.destination}', '{self.downloaded}', '{self.infected}', '{self.contacttype}')"""


# Define the Role data-model
class Role(db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer, primary_key=True)
    roleId = db.Column(db.String, unique=True,
                       nullable=False, default=generate_key)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String, nullable=False)

    def __repr__(self):
        return f"Role('{self.id}','{self.name}', '{self.description}', '{self.roleId}')"

class WorldUpdate(db.Model):
    __tablename__ = 'world_update'
    id = db.Column(db.Integer, primary_key=True)
    context = db.Column(db.String(11), nullable=False)
    data = db.Column(db.String)
    lastupdate = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"WorldUpdate('{self.id}', '{self.context}','{self.data}','{self.lastupdate}')"


class Notification(db.Model):
    __tablename__ = 'notification'
    id = db.Column(db.Integer, primary_key=True)
    usercode = db.Column(db.String, nullable=False)
    data = db.Column(db.String)
    
    def __repr__(self):
        return f"Notification('{self.id}','{self.usercode}','{self.data}')"


class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String, nullable=False)
    subject = db.Column(db.String, nullable=False)
    msg = db.Column(db.String, nullable=False)
    senddate = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    readstatus = db.Column(db.Boolean, nullable=False, default=0)
    email = db.Column(db.String, nullable=False)
    def __repr__(self):
        return f"Message('{self.id}','{self.userid}','{self.subject}','{self.msg}','{self.senddate}','{self.readstatus}','{self.email}')"



class RoleApplication(db.Model):
    __tablename__ = 'role_application'
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    roleId = db.Column(db.String, nullable=False)
    organization_type = db.Column(db.String, nullable=False)
    organization_name = db.Column(db.String, nullable=False)
    reason = db.Column(db.String, nullable=False)
    organization_role = db.Column(db.String, nullable=False)
    application_status = db.Column(db.String, nullable=False, default='pending')
    application_date = db.Column(db.DateTime, nullable=False)
    
    def __repr__(self):
        return f"RoleApplication('{self.id}','{self.sender}','{self.email}','{self.roleId}','{self.organization_type}','{self.organization_name}','{self.reason}','{self.organization_role}','{self.application_date}','{self.application_status}')"