"""Python Flask WebApp Auth0 integration example
"""
from functools import wraps
import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template, request
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode
from boto3.dynamodb.conditions import Key

import constants

import boto3 # new
from botocore.exceptions import ClientError  # new


ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)


headings  = ('Organization_ID', 'Organization_Name', 'Operator_num1', 'Operator_num2', 'Operator_num3')

# abc = auth0.organisation_name
__TableName__ = "twilioDB" # __TableName__ = abc

client = boto3.client('dynamodb')

DB = boto3.resource('dynamodb')
table = DB.Table(__TableName__)
response = table.scan()


AUTH0_CALLBACK_URL = env.get(constants.AUTH0_CALLBACK_URL)
AUTH0_CLIENT_ID = env.get(constants.AUTH0_CLIENT_ID)
AUTH0_CLIENT_SECRET = env.get(constants.AUTH0_CLIENT_SECRET)
AUTH0_DOMAIN = env.get(constants.AUTH0_DOMAIN)
AUTH0_BASE_URL = 'https://' + AUTH0_DOMAIN
AUTH0_AUDIENCE = env.get(constants.AUTH0_AUDIENCE)
AUTH0_ORG_ID = env.get(constants.AUTH0_ORG_ID)
# AUTH0_ORG_NAME = env.get(constants.AUTH0_ORG_NAME)

app = Flask(__name__, static_url_path='/public', static_folder='./public')
app.secret_key = constants.SECRET_KEY
app.debug = True


# @app.route('/table')    
# def table():
#     return render_template('table.html', headings=headings, data=response['Items'])

@app.errorhandler(Exception)
def handle_auth_error(ex):
    response = jsonify(message=str(ex))
    response.status_code = (ex.code if isinstance(ex, HTTPException) else 500)
    return response


oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    # org_id=AUTH0_ORG_ID,
    # org_name=AUTH0_ORG_NAME,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=AUTH0_BASE_URL + '/oauth/token',
    authorize_url=AUTH0_BASE_URL + '/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if constants.PROFILE_KEY not in session:
            return redirect('/login')
        return f(*args, **kwargs)

    return decorated


# Controllers API
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/callback')
def callback_handling():
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()
    session[constants.JWT_PAYLOAD] = userinfo
    session[constants.PROFILE_KEY] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture'],
        'org_id': userinfo['org_id'],
        # 'org_name': userinfo['org_name']
    }
    return redirect('/dashboard')


@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri=AUTH0_CALLBACK_URL, audience=AUTH0_AUDIENCE)


@app.route('/logout')
def logout():
    session.clear()
    params = {'returnTo': url_for('home', _external=True), 'client_id': AUTH0_CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))


@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session[constants.PROFILE_KEY],
                           userinfo_pretty=json.dumps(session[constants.JWT_PAYLOAD], indent=4))

@app.route('/table1')    
def table1():
    table = DB.Table(__TableName__)
    userinfo=session[constants.PROFILE_KEY]
    response = table.query(
  KeyConditionExpression=Key('Organization_ID').eq(userinfo['org_id'])
)
    return render_template('table.html', headings=headings, data=response['Items'])

@app.route('/insert', methods=['post']) # new
def insert():
    userinfo=session[constants.PROFILE_KEY]
    if request.method == 'POST':
        organisation = request.form['Organization_Name']
        operatornum1 = request.form['Operator_num1']
        operatornum2 = request.form['Operator_num2']
        operatornum3 = request.form['Operator_num3']
        
        table = DB.Table('ins_data')
        
        table.put_item(
                Item={
        'Organization_ID': userinfo['org_id'],            
        'Organization_Name': organisation,
        'Operator_num1': operatornum1,
        'Operator_num2': operatornum2,
        'Operator_num3': operatornum3            }
        )
    
        #return render_template('login.html',msg = msg)
    return redirect('/dashboard')

@app.route('/fill_data') # new
def fill_data():
    return render_template('fill_data.html',userinf=session[constants.PROFILE_KEY])

@app.route('/table1/edit_item/<id>')
def edit_item(id):
    table = DB.Table('ins_data')
    response = table.get_item(
        Key={
            'Organization_ID': id,
            # 'Organization_Name': name
            }
        )
    return render_template('edit_data.html', field=response['Item'])

# @app.route('/update_item/<id>/<name>', methods=['post'])
# def update_item(id,name):
#     if request.method == 'POST':
#         table = DB.Table('ins_data')

#         table.update_item(
#             Key={
#                 'Organization_ID': id,
#                 'Organization_Name': name
#             },
#             UpdateExpression="set Operator_num1=:o1, Operator_num2=:o2, Operator_num3=:o3",
#             ExpressionAttributeValues={
#                 ':o1': request.form['Operator_num1'],
#                 ':o2': request.form['Operator_num2'],
#                 ':o3': request.form['Operator_num3']
#             },
#             ReturnValues="UPDATED_NEW"
#         )
#         return redirect('/table1')

@app.route('/update_item/<id>', methods=['post'])
def update_item(id):
    if request.method == 'POST':
        table = DB.Table('ins_data')
        table.update_item(
        Key={
                'Organization_ID': id,
            },
        UpdateExpression="set Organization_Name=:oname, Operator_num1=:o1, Operator_num2=:o2, Operator_num3=:o3",
            ExpressionAttributeValues={
                ':oname': request.form['Organization'],
                ':o1': request.form['Operator_num1'],
                ':o2': request.form['Operator_num2'],
                ':o3': request.form['Operator_num3']
            },
            ReturnValues="UPDATED_NEW"
        )

        # table.update_item(
        #     Key={
        #         'Organization_ID': id,
        #         'Organization_Name': name
        #     },
        #     UpdateExpression="set Operator_num1=:o1, Operator_num2=:o2, Operator_num3=:o3",
        #     ExpressionAttributeValues={
        #         ':o1': request.form['Operator_num1'],
        #         ':o2': request.form['Operator_num2'],
        #         ':o3': request.form['Operator_num3']
        #     },
        #     ReturnValues="UPDATED_NEW"
        # )
        return redirect('/table1')



#if __name__ == "__main__":
 #   app.run(host='0.0.0.0', port=env.get('PORT', 80))
