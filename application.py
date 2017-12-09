from models import Base, User,Category,Item
from flask import Flask, jsonify, request, url_for, abort, g, render_template,redirect,flash
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine,desc
from flask_httpauth import HTTPBasicAuth
import json
import random, string

#NEW IMPORTS
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
import requests

from flask import session as login_session

auth = HTTPBasicAuth()


engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']


# CRUD Functionality
def showCategories():
    return session.query(Category).all()

def showCategory(name):
    category = session.query(Category).filter_by(name=name).first()
    return category

def addCategory(name):
    try:
        new_category = Category(name=name,user=getCurrentUser())
        session.add(new_category)
        session.commit()
        return True
    except:
        return False

def showItems(category_id,limit):
    if category_id:
        items = session.query(Item).order_by(desc(Item.id)).filter_by(category_id = category_id).all()
    elif limit:
        items = session.query(Item).order_by(desc(Item.id)).limit(limit)
    else:
        items = session.query(Item).order_by(desc(Item.id)).all()
    return items

def showItem(categoryName,itemName):
    category_id = showCategory(categoryName).id
    item = session.query(Item).filter_by(name=itemName,category_id=category_id).first()
    return item

def newItem(name,description,categoryName):
    try:
        category = showCategory(categoryName)
        new_item = Item(name=name,description=description,category=category,user=getCurrentUser())
        session.add(new_item)
        session.commit()
        return True
    except:
        return False

def editItem(item,name,description,categoryName):
    try:
        item.name = name
        item.description = description
        category = showCategory(categoryName)
        item.category = category
        session.add(item)
        session.commit()
        return item
    except:
        return False

def deleteItem(item):
    try:
        session.delete(item)
        session.commit()
        return True
    except:
        return False

def isLoggedIn():
    return 'username' in login_session

def getUserByEmail(email):
    try:
        user = session.query(User).filter_by(email=email).first()
        return user
    except:
        return False

def getCurrentUser():
    try:
        user = session.query(User).filter_by(id=login_session['user_id']).first()
        return user
    except:
        return False

def createUser(user):
    try:
        new_user = User(username=user.username,picture=user.picture,email=user.email)
        session.add(new_user)
        session.commit()
        return new_user
    except:
        return False

@app.route('/')
@app.route('/catalog')
def default():
    categories = showCategories()
    items = showItems(None,10)
    return render_template('catalog.html',categories = categories, items=items)

@app.route('/catalog/<categoryName>')
def categoryDisplay(categoryName):
    if categoryName!='default':
        cat = showCategory(categoryName)
        items = showItems(cat.id,None)
        return render_template('category_items.html',items=items,category=cat)
    elif categoryName=='default':
        return redirect(url_for('default'))
    else:
        ## error
        flash(u'Error retreiving category','danger')
        return redirect(url_for('default'))

@app.route('/catalog/<categoryName>/new',methods = ['GET','POST'])
def newCategoryItem(categoryName):
    if not isLoggedIn():
        flash('login is required to create a new item','warning')
        return redirect('/login')
    if request.method == 'POST':
        try:
            name = request.form["name"]
            description = request.form["description"]
            # print categoryName
            if 'categoryName' in request.form:
                catName = request.form["categoryName"]
            else:
                catName = categoryName
            # print catName
            if name and description and catName:
            # Success flash
                newItem(name,description,catName)
                flash(u'Success! item Created successfuly','success')
                return redirect(url_for('categoryDisplay',categoryName=catName))
            else:
                # Failed flash
                flash(u'Error One of the fields is empty, please try again!','danger')
                return redirect(url_for('newCategoryItem',categoryName=catName))
        except:
            # Failed flash
            flash('Server Error, please try again later','danger')
            return redirect(url_for('categoryDisplay',categoryName=categoryName))
    else:
        return render_template('category_item_new.html',categories=showCategories(),categoryName=categoryName)

@app.route('/catalog/new', methods = ['GET','POST'])
def newCategory():
    if not isLoggedIn():
        flash('login is required to create a new category','warning')
        return redirect('/login')
    if request.method == 'POST':
        try:
            name = request.form["name"]
            if name:
                # Success flash
                flash(u'Success!, Category created successfuly','success')
                addCategory(name)
                return redirect(url_for('default'))
            else:
                # Failed flash
                flash(u'Error creating category, please try again later','danger')
                return render_template('new_category.html')
        except:
            # Failed flash
            flash(u'Server Error, please try again later','danger')
            return render_template('new_category.html')
    else:
        return render_template('new_category.html')

@app.route('/catalog/<categoryName>/<itemName>')
def categoryItem(categoryName,itemName):
    it = showItem(categoryName,itemName)
    return render_template('category_item.html',item=it)

@app.route('/catalog/<categoryName>/<itemName>/edit', methods = ['GET','POST'])
#@auth.login_required
def categoryItemEdit(categoryName,itemName):
    if not isLoggedIn():
        flash('login is required to edit this item','warning')
        return redirect('/login')
    itm = showItem(categoryName,itemName)
    if login_session['user_id'] != itm.user_id:
        flash('you are not authorized to edit this item','danger')
        return redirect(url_for('categoryItem',categoryName=categoryName,itemName=itemName))
    if request.method == 'POST':
        try:
            it = editItem(it,request.form["name"],request.form["description"],request.form["categoryName"])
            # Success flash
            flash(u'Success!, item saved successfuly','success')
            return redirect(url_for('categoryItem',categoryName=itm.category.name,itemName=itm.name))
        except:
            # error flash
            flash(u'Error creating item, please try again later','danger')
            return redirect(url_for('categoryItem',categoryName=itm.category.name,itemName=itm.name))
    else:
        return render_template('category_item_edit.html',item=itm,categories=showCategories())

@app.route('/catalog/<categoryName>/<itemName>/delete')
def categoryItemDelete(categoryName,itemName):
    if not isLoggedIn():
        flash('login is required to delete this item','warning')
        return redirect('/login')
    creator = showItem(categoryName,itemName).user
    if login_session['user_id'] != creator.id:
        flash('you are not authorized to delete this item','danger')
        return redirect(url_for('categoryItem',categoryName=categoryName,itemName=itemName))
    it = showItem(categoryName,itemName)
    return render_template('category_item_delete.html',item=it)

@app.route('/catalog/<categoryName>/<itemName>/deleteConfirm')
def categoryItemDeleteConfirm(categoryName,itemName):
    if not isLoggedIn():
        flash('login is required to delete this item','warning')
        return redirect('/login')
    creator = showItem(categoryName,itemName).user
    if login_session['user_id'] != creator.id:
        flash('you are not authorized to edit this item','danger')
        return redirect(url_for('categoryItem',categoryName=categoryName,itemName=itemName))
        it = showItem(categoryName,itemName)
        try:
            it = deleteItem(it)
            # Success flash
            flash(u'Success!, item deleted successfuly','success')
            return redirect(url_for('categoryDisplay',categoryName=categoryName))
        except:
            # error flash
            flash(u'Server Error, please try again later','danger')
            return redirect(url_for('categoryDisplay',categoryName=categoryName))

@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state,client_id=CLIENT_ID)

@app.route('/oauth/logout')
def oauthDisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print('In gdisconnect access token is %s', access_token)
    print('User name is: ')
    print(login_session['username'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is ')
    print(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['logged_in']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash('Successfully disconnected.','success')
        return redirect(url_for('default'))
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        flash('Failed to revoke token for given user.','danger')
        return redirect(url_for('default'))

@app.route('/oauth/<provider>', methods=['POST'])
def oauthConnect(provider):
    if provider == 'google':
        # Validate state token
        if request.args.get('state') != login_session['state']:
            response = make_response(json.dumps('Invalid state parameter.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        # Obtain authorization code
        code = request.data

        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(code)
        except FlowExchangeError:
            response = make_response(
                json.dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Check that the access token is valid.
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
               % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Verify that the access token is used for the intended user.
        gplus_id = credentials.id_token['sub']
        if result['user_id'] != gplus_id:
            response = make_response(
                json.dumps("Token's user ID doesn't match given user ID."), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Verify that the access token is valid for this app.
        if result['issued_to'] != CLIENT_ID:
            response = make_response(
                json.dumps("Token's client ID does not match app's."), 401)
            print "Token's client ID does not match app's."
            response.headers['Content-Type'] = 'application/json'
            return response

        stored_access_token = login_session.get('access_token')
        stored_gplus_id = login_session.get('gplus_id')
        if stored_access_token is not None and gplus_id == stored_gplus_id:
            response = make_response(json.dumps('Current user is already connected.'),
                                     200)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Store the access token in the session for later use.
        login_session['access_token'] = credentials.access_token
        login_session['gplus_id'] = gplus_id

        # Get user info
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = requests.get(userinfo_url, params=params)

        data = answer.json()

        login_session['username'] = data['name']
        login_session['picture'] = data['picture']
        login_session['email'] = data['email']

        output = ''
        output += '<h1>Welcome, '
        output += login_session['username']
        output += '!</h1>'
        output += '<img src="'
        output += login_session['picture']
        output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

        user = session.query(User).filter_by(email=login_session['email']).first()
        if not user:
            user = User(username=login_session['username'],picture=login_session['picture'],email=login_session['email'])
            session.add(user)
            session.commit()

        login_session['user_id'] = user.id
        login_session['logged_in'] = True

        flash("you are now logged in as %s" % login_session['username'])
        print "done!"
        user = getUserByEmail(login_session['email'])
        # token = user.generate_auth_token(600)
        # return jsonify({'token': token.decode('ascii')})
        return redirect(url_for('default'))


@app.route('/api/users/<int:id>')
def get_user(id):
    user = session.query(User).filter_by(id=id).one()
    if not user:
        abort(400)
    return jsonify({'username': user.username})

if __name__ == '__main__':
    app.debug = True
    app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    app.run(host='0.0.0.0', port=5000)
