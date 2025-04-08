from hashlib import sha256
import hmac
import os
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api, reqparse, fields, marshal_with, abort
from flask_cors import CORS
from dotenv import load_dotenv
import base64

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
api = Api(app)
cors = CORS(app)


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


class Webhook(Resource):
    def post(self):
        # Verify Signature
        if "X-Tiltify-Signature" not in request.headers:
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
            abort(403)


        # Process Request
        args = total_args.parse_args()
        total = TotalModel.query.first()

        if not total:
            total = TotalModel(
                total=f'${args["data"]["amount_raised"]["value"]}'
            )
            db.session.add(total)
            db.session.commit()
            return None, 201

        total.total = f'${args["data"]["amount_raised"]["value"]}'
        db.session.commit()
        return None, 200


api.add_resource(Total, '/hot/total')
api.add_resource(Webhook, '/hot/webhook')

if __name__ == "__main__":
    load_dotenv()

    with app.app_context():
        db.create_all()

    app.run()
