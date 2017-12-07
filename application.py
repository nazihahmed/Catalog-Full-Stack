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
        new_category = Category(name=name)
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
        new_item = Item(name=name,description=description,category=category)
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

@auth.login_required
@app.route('/catalog/<categoryName>/new',methods = ['GET','POST'])
def newCategoryItem(categoryName):
    if request.method == 'POST':
        try:
            name = request.form["name"]
            description = request.form["description"]
            print categoryName
            if 'categoryName' in request.form:
                catName = request.form["categoryName"]
            else:
                catName = categoryName
            print catName
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

@auth.login_required
@app.route('/catalog/new', methods = ['GET','POST'])
def newCategory():
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

@auth.login_required
@app.route('/catalog/<categoryName>/<itemName>/edit', methods = ['GET','POST'])
#@auth.login_required
def categoryItemEdit(categoryName,itemName):
    it = showItem(categoryName,itemName)
    if request.method == 'POST':
        try:
            it = editItem(it,request.form["name"],request.form["description"],request.form["categoryName"])
            # Success flash
            flash(u'Success!, item saved successfuly','success')
            return redirect(url_for('categoryItem',categoryName=it.category.name,itemName=it.name))
        except:
            # error flash
            flash(u'Error creating item, please try again later','danger')
            return redirect(url_for('categoryItem',categoryName=it.category.name,itemName=it.name))
    else:
        return render_template('category_item_edit.html',item=it,categories=showCategories())

@auth.login_required
@app.route('/catalog/<categoryName>/<itemName>/delete')
#@auth.login_required
def categoryItemDelete(categoryName,itemName):
        it = showItem(categoryName,itemName)
        return render_template('category_item_delete.html',item=it)

@auth.login_required
@app.route('/catalog/<categoryName>/<itemName>/deleteConfirm')
#@auth.login_required
def categoryItemDeleteConfirm(categoryName,itemName):
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

# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)

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
    app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    app.run(host='0.0.0.0', port=5000)
