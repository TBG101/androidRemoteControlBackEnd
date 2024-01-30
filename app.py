from datetime import timedelta
from json import loads
from re import match
from flask import Flask, jsonify,  request
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from bcrypt import hashpw, gensalt, checkpw
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY")  # "adSF41zef3X4d>51Hsxd4WSx4N"
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "SQLALCHEMY_DATABASE_URI")  # "sqlite:///db.sqlite3"
app.config['JWT_SECRET_KEY'] = os.environ.get("JWT_SECRET_KEY")

db = SQLAlchemy(app=app)
socketio = SocketIO(app, cors_allowed_origins="*")
jwt = JWTManager(app)


last_call_time = None


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self, email, password, name):
        self.name = name
        self.email = email
        self.password = hashpw(password.encode(
            'utf-8'), gensalt()).decode('utf-8')

    def checkPassword(self, password):
        checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))


# { "email": [ list of sid of phones here | "sid_here","sid_here "]}
connected_phones = {}
connected_pcs = {}


with app.app_context():
    db.create_all()


def is_user_connected(user_sid):
    return socketio.server.manager.is_connected("/", user_sid)


def validate_email(email):
    if match(r"[^@]+@[^@]+\.[^@]+", email):
        return True
    return False


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Missing username or email or password'}), 400
    if (not validate_email(email=email)):
        return jsonify({'message': 'Email is not Email type'}), 400

    existing_user = User.query.filter_by(email=email).first()

    if (existing_user):
        return jsonify({'message': 'Email Exists'}), 400

    new_user = User(name=username, email=email, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST', "GET"])
def login():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()

    if (not user or not user.checkPassword(password)):
        return jsonify({'message': 'Invalid username or password'}), 401

    expires = timedelta(days=3650)
    access_token = create_access_token(identity=email, expires_delta=expires)

    return jsonify(access_token=access_token), 200


@socketio.on("connect")
@jwt_required()
def handle_connect():
    userConnected = get_jwt_identity()
    print(f"user connect {userConnected}")
    hardware = request.headers.get("hardware")
    socketio.emit("getsid", str(request.sid), room=request.sid)

    if (hardware):
        if (hardware == "phone"):
            if (connected_phones.get(userConnected)):
                print(request.sid)
                connected_phones[userConnected].append(str(request.sid))
            else:
                connected_phones[userConnected] = [str(request.sid)]
        elif (hardware == "pc"):
            if (connected_pcs.get(userConnected)):
                print(request.sid)
                connected_pcs[userConnected].append(str(request.sid))
            else:
                connected_pcs[userConnected] = [str(request.sid)]

    if (connected_phones.get(userConnected)):
        items_to_keep = [
            item for item in connected_phones[userConnected] if not is_user_connected(item)]
        connected_phones[userConnected].clear()
        connected_phones[userConnected].extend(items_to_keep)
    if (connected_pcs.get(userConnected) != None):
        # need to remove this part
        items_to_keep = [
            item for item in connected_pcs[userConnected] if not is_user_connected(item)]
        connected_pcs[userConnected].clear()
        connected_pcs[userConnected].extend(items_to_keep)
        if (len(connected_pcs.get(userConnected)) > 0 and connected_phones.get(userConnected)):
            for i in connected_pcs[userConnected]:
                socketio.emit("getphones", str(
                    connected_phones[userConnected]), room=i)
    print(connected_pcs)
    print(connected_phones)


@app.route("/protected", methods=["GET"])
@jwt_required()
def checkAuth():
    return jsonify({"message": "Authorized"}), 200


@app.route("/getphones", methods=["GET"])
@jwt_required()
def getPhones():
    current_user = get_jwt_identity()
    print(connected_pcs)
    if (connected_phones.get(current_user) != None):
        return jsonify({"phones": str(connected_phones[current_user])}), 200
    else:
        return jsonify({"phones": "none"}), 200


@socketio.on("disconnect")
@jwt_required()
def handle_disconnect():
    userConnected = get_jwt_identity()
    hardware = request.headers.get("hardware")
    if (hardware):
        if (hardware == "phone"):
            if (connected_phones.get(userConnected)):
                try:
                    connected_phones[userConnected].remove(str(request.sid))
                except:
                    print("no item to remove")
        elif (hardware == "pc"):
            if (connected_pcs.get(userConnected)):
                try:
                    connected_pcs[userConnected].remove(str(request.sid))
                except:
                    print("no item to remove")
    if (connected_phones.get(userConnected)):
        items_to_keep = [
            item for item in connected_phones[userConnected] if not is_user_connected(item)]
        connected_phones[userConnected].clear()
        connected_phones[userConnected].extend(items_to_keep)
    if (connected_pcs.get(userConnected)):
        items_to_keep = [
            item for item in connected_pcs[userConnected] if not is_user_connected(item)]
        connected_pcs[userConnected].clear()
        connected_pcs[userConnected].extend(items_to_keep)
        if (len(connected_pcs.get(userConnected)) > 0 and connected_phones.get(userConnected)):
            for i in connected_pcs[userConnected]:
                socketio.emit("getphones", str(
                    connected_phones[userConnected]), room=i)
    print(connected_pcs)
    print(connected_phones)


@socketio.on('message')
@jwt_required()
def handle_message(msg):
    print(msg)
    targetSid = msg["target"]
    print("received")
    print('Message:', msg)
    socketio.emit('message', msg, skip_sid=request.sid, room=targetSid)


@socketio.on("image_event")
@jwt_required()
def handle_image(data):
    x = loads(data)
    try:
        targetSid = x["target"]
        img = x["image"]
    except e:
        targetSid = None
        img = None
    try:
        if (img and targetSid):
            socketio.emit("image_event", img,
                          skip_sid=request.sid, room=targetSid)
    except Exception as e:
        print(str(e))
        print("ERROR: uploading image")


@socketio.on("createconnection")
@jwt_required()
def handle_create_connection(data):
    target = data["target"]
    print(f"connection with {target} and {request.sid}")
    socketio.emit("createconnection", str(request.sid), room=target)


if __name__ == '__main__':
    socketio.run(app, host="192.168.1.13", port=5000, debug=True)
