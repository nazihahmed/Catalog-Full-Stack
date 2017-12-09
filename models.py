from sqlalchemy import Column,Integer,String,ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
import random, string
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
import os
import sys

Base = declarative_base()

#You will use this secret key to create and verify your tokens
secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32))
    picture = Column(String)
    email = Column(String,index=True)
    # password_hash=Column(String(64))
    # password_hash = Column(String(64))

    # def hash_password(self, password):
    #     self.password_hash = pwd_context.encrypt(password)
    #
    # def verify_password(self, password):
    #     return pwd_context.verify(password, self.password_hash)
    #Add a method to generate auth tokens here
    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in = expiration)
        return s.dumps({'id':self.id})
    #Add a method to verify auth tokens here
    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user_id = data['id']
        return user_id

class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    # serializeable format
    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
                'id' : self.id,
                'name' : self.name,
                'user_id': self.user_id
            }


class Item(Base):
    __tablename__ = 'item'

    name = Column(String(150), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    # serializeable format
    @property
    def serialize(self):
        return {
            'name': self.name,
            'description': self.description,
            'category_id': self.category_id,
            'user_id': self.user_id,
            'id': self.id
        }


engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)
