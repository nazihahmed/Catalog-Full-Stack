from models import Base, User,Category,Item
from flask import Flask, jsonify, request, url_for, abort, g, render_template,redirect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

from flask.ext.httpauth import HTTPBasicAuth
import json

#NEW IMPORTS
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
import requests

auth = HTTPBasicAuth()


engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)

# categories = session.query(Category).all()
# session.delete(categories)
# session.commit()
# # Menu for UrbanBurger
# category1 = Category(name="Basketball")
# #
# session.add(category1)
# session.commit()
# #
# item1 = Item(name="Veggie Burger", description="Juicy grilled veggie patty with tomato mayo and lettuce", category=category1)
# session.add(item1)
# session.commit()
#CLIENT_ID = json.loads(
#    open('client_secrets.json', 'r').read())['web']['client_id']


# CRUD Functionality
def showCategories():
    return session.query(Category).all()

def showCategory(name):
    category = session.query(Category).filter_by(name=name).first()
    return category

def newCategory(name):
    new_category = Category(name=name)
    session.add(new_category)
    session.commit()

def showItems(category_id,limit):
    if category_id:
        items = session.query(Item).filter_by(category_id = category_id).all()
    elif limit:
        items = session.query(Item).limit(limit)
    else:
        items = session.query(Item).all()
    return items

def showItem(categoryName,itemName):
    category_id = showCategory(categoryName).id
    item = session.query(Item).filter_by(name=itemName,category_id=category_id).first()
    return item

def newItem(name,description,category_id):
    category = session.query(Category).filter_by(id=category_id).first()
    new_item = Item(name=name,description=description,category=category)
    session.add(new_item)
    session.commit()
    return new_item

def editItem(item,name,description):
    item['name'] = name
    item['description'] = description
    session.add(item)
    session.commit()
    return item

def deleteItem(item_id):
    item = session.query(Item).filter_by(id=item_id).first()
    session.delete(item)
    session.commit()
    return item



@auth.verify_password
def verify_password(username_or_token, password):
    #Try to see if it's a token first
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id = user_id).one()
    else:
        user = session.query(User).filter_by(username = username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@app.route('/')
def default():
    categories = showCategories()
    items = showItems(None,10)
    return render_template('catalog.html',categories = categories, items=items)

@app.route('/clientOAuth')
def start():
    return render_template('clientOAuth.html')

@app.route('/catalog/<categoryName>')
def categoryDisplay(categoryName):
    cat = showCategory(categoryName)
    items = showItems(cat.id,None)
    return render_template('category_items.html',items=items)

@app.route('/catalog/new', methods = ['GET','POST'])
def newCat():
    if request.method == 'POST':
        newcat = newCategory(name=request.form["name"])
        return redirect('/')
    else:
        return redirect('/')

@app.route('/catalog/<categoryName>/<itemName>', methods = ['GET','POST'])
def categoryItem(categoryName,itemName):
    it = showItem(categoryName,itemName)
    if request.method == 'POST':
        return render_template('category_item.html',item=it)
    else:
        return render_template('category_item.html',item=it)

@app.route('/catalog/<categoryName>/<itemName>/edit', methods = ['GET','POST'])
#@auth.login_required
def categoryItemEdit(categoryName,itemName):
    it = showItem(categoryName,itemName)
    if request.method == 'POST':
        editItem(it,request.form["name"],request.form["description"])
        return redirect
    else:
        return render_template('category_item_edit.html',item=it)

@app.route('/catalog/<categoryName>/<itemName>/delete')
#@auth.login_required
def categoryItemDelete(categoryName,itemName):
    if request.method == 'POST':
        return render_template('category_item.html',category=category,item=item)
    else:
        it = showItem(categoryName,itemName)
        return render_template('category_item_delete.html',item=it)

@app.route('/oauth/<provider>', methods = ['POST'])
def login(provider):
    #STEP 1 - Parse the auth code
    auth_code = request.json.get('auth_code')
    print "Step 1 - Complete, received auth code %s" % auth_code
    if provider == 'google':
        #STEP 2 - Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Check that the access token is valid.
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'

        # # Verify that the access token is used for the intended user.
        # gplus_id = credentials.id_token['sub']
        # if result['user_id'] != gplus_id:
        #     response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
        #     response.headers['Content-Type'] = 'application/json'
        #     return response

        # # Verify that the access token is valid for this app.
        # if result['issued_to'] != CLIENT_ID:
        #     response = make_response(json.dumps("Token's client ID does not match app's."), 401)
        #     response.headers['Content-Type'] = 'application/json'
        #     return response

        # stored_credentials = login_session.get('credentials')
        # stored_gplus_id = login_session.get('gplus_id')
        # if stored_credentials is not None and gplus_id == stored_gplus_id:
        #     response = make_response(json.dumps('Current user is already connected.'), 200)
        #     response.headers['Content-Type'] = 'application/json'
        #     return response
        print "Step 2 Complete! Access Token : %s " % credentials.access_token

        #STEP 3 - Find User or make a new one

        #Get user info
        h = httplib2.Http()
        userinfo_url =  "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt':'json'}
        answer = requests.get(userinfo_url, params=params)

        data = answer.json()

        name = data['name']
        picture = data['picture']
        email = data['email']



        #see if user exists, if it doesn't make a new one
        user = session.query(User).filter_by(email=email).first()
        if not user:
            user = User(username = name, picture = picture, email = email)
            session.add(user)
            session.commit()



        #STEP 4 - Make token
        token = user.generate_auth_token(600)



        #STEP 5 - Send back token to the client
        return jsonify({'token': token.decode('ascii')})

        #return jsonify({'token': token.decode('ascii'), 'duration': 600})
    else:
        return 'Unrecoginized Provider'

@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})



@app.route('/users', methods = ['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        print "missing arguments"
        abort(400)

    if session.query(User).filter_by(username = username).first() is not None:
        print "existing user"
        user = session.query(User).filter_by(username=username).first()
        return jsonify({'message':'user already exists'}), 200#, {'Location': url_for('get_user', id = user.id, _external = True)}

    user = User(username = username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify({ 'username': user.username }), 201#, {'Location': url_for('get_user', id = user.id, _external = True)}

@app.route('/api/users/<int:id>')
def get_user(id):
    user = session.query(User).filter_by(id=id).one()
    if not user:
        abort(400)
    return jsonify({'username': user.username})

@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({ 'data': 'Hello, %s!' % g.user.username })

if __name__ == '__main__':
    app.debug = True
    #app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    app.run(host='0.0.0.0', port=5000)
