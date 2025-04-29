from hashlib import sha256
import hmac
import os
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api, reqparse, fields, marshal_with, abort
from flask_cors import CORS
from dotenv import load_dotenv
import base64
import requests
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
import datetime

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE', '')
db = SQLAlchemy(app)
api = Api(app)
cors = CORS(app)
scheduler = BackgroundScheduler()


class TwitchAuthModel(db.Model):
    token = db.Column(db.String(100), primary_key=True)
    expires = db.Column(db.DateTime)

    def __repr__(self):
        return f'TwitchAuth(token = {self.token}, expires = {self.expires})'


def twitch_auth():
    with app.app_context():
        token = TwitchAuthModel.query.first()
        if token and token.expires > datetime.datetime.now():
            return token.token

        resp = requests.post(
            url='https://id.twitch.tv/oauth2/token',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data={
                'client_id': os.environ.get('TWITCH_CLIENT_ID', ''),
                'client_secret': os.environ.get('TWITCH_CLIENT_SECRET', ''),
                'grant_type': 'client_credentials'
            }
        )

        if not resp.ok:
            raise Exception("Failed to authenticate with Twitch", resp.text)

        data = resp.json()

        if not token:
            token = TwitchAuthModel(
                token=data['access_token'],
                expires=datetime.datetime.now(
                ) + datetime.timedelta(seconds=data['expires_in'])
            )
            db.session.add(token)
        else:
            token.token = data['access_token']
            token.expires = datetime.datetime.now(
            ) + datetime.timedelta(seconds=data['expires_in'])
        db.session.commit()

        return token.token


class TotalModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    total = db.Column(db.String(20))

    def __repr__(self):
        return f'Total(total = {self.total})'


totalFields = {
    'total': fields.String
}

total_args = reqparse.RequestParser()
total_args.add_argument('data', type=dict, required=True)


class Total(Resource):
    @marshal_with(totalFields)
    def get(self):
        return TotalModel.query.first_or_404()


class StreamModel(db.Model):
    name = db.Column(db.String(100), primary_key=True)
    status = db.Column(db.Boolean)

    def __repr__(self):
        return f'Stream(id = {self.id}, name = {self.name}, status = {self.status})'


streamFields = {
    'streams': fields.List
}


class Stream(Resource):
    def get(self):
        live = StreamModel.query.filter_by(status=True).all()
        return [s.name for s in live]


def check_streams():
    with app.app_context():
        channels = [s.name for s in StreamModel.query.all()]
        resp = requests.get(
            url='https://api.twitch.tv/helix/streams',
            params=[('user_login', c) for c in channels] + [('first', 100)],
            headers={
                'Authorization': f'Bearer {twitch_auth()}',
                'Client-Id': os.environ.get('TWITCH_CLIENT_ID', '')
            }
        )

        if not resp.ok:
            raise Exception("Failed to get live channels")

        data = resp.json()
        live = [c["user_login"] for c in data["data"]]

        liveChannels = StreamModel.query.filter(StreamModel.name.in_(live)).all()
        offlineChannels = StreamModel.query.filter(StreamModel.name.not_in(live)).all()

        for c in liveChannels:
            c.status = True
        for c in offlineChannels:
            c.status = False

        db.session.commit()


class Webhook(Resource):
    def post(self):
        # Verify Signature
        if "X-Tiltify-Signature" not in request.headers:
            print('Invalid Headers')
            abort(403)
        signature = request.headers.get("X-Tiltify-Signature", "")
        timestamp = request.headers.get("X-Tiltify-Timestamp", "")
        body = request.get_data(as_text=True)
        payload = f'{timestamp}.{body}'.encode("utf-8")

        # Generate our own signature based on the request payload
        secret = os.environ.get('WEBHOOK_SECRET', '').encode("utf-8")
        mac = hmac.new(secret, msg=payload, digestmod=sha256)

        # Ensure the two signatures match
        if not str(base64.b64encode(mac.digest()))[2:-1] == str(signature):
            print("Signature Mismatch")
            abort(403)

        # Process Request
        args = total_args.parse_args()
        total = TotalModel.query.first()

        if not total:
            total = TotalModel(
                total=f'${args["data"]["total_amount_raised"]["value"]}'
            )
            db.session.add(total)
            db.session.commit()
            return None, 201

        total.total = f'${args["data"]["total_amount_raised"]["value"]}'
        db.session.commit()
        return None, 200


api.add_resource(Total, '/hot/total')
api.add_resource(Stream, '/hot/streams')
api.add_resource(Webhook, '/hot/webhook')

scheduler.add_job(func=check_streams, trigger='interval', seconds=60)
scheduler.start()

atexit.register(lambda: scheduler.shutdown())

if __name__ == "__main__":
    app.run()
