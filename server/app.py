#!/usr/bin/env python3

from flask import request, session, jsonify, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        json = request.get_json()
        user = User(
            username = json.get('username'),
            image_url = json.get('image_url'),
            bio = json.get('bio')
        )
        user.password_hash = json.get('password')
        
        try:
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return user.to_dict(), 201
        except IntegrityError as e:
            db.session.rollback()
            return make_response({"message":"Unprocessable Entity"}, 422)

class CheckSession(Resource):
    def get(self):
        user = User.query.filter(User.id == session['user_id']).first()
        if user:
            return user.to_dict(), 200
        else:
            return {}, 401

class Login(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')

        user = User.query.filter(User.username == username).first()
        if user:
            if user.authenticate(password):
                session['user_id'] = user.id
                return user.to_dict(), 200
        else:
            return make_response({"error":"Unauthorized"}, 401)

class Logout(Resource):
    def delete(self):
        if session['user_id']:
            session['user_id'] = None
            return {}, 204
        else:
            return make_response({"error":"unauthorized"}, 401)


class RecipeIndex(Resource):
    def get(self):
        if not session['user_id']:
            return make_response({"error":"unauthorized"}, 401)
        else:
            user_id = session['user_id']
            recipes = [recipe.to_dict() for recipe in Recipe.query.filter(Recipe.user_id == user_id).all()]
            return recipes, 200
        
    def post(self):
        json = request.get_json()
        if not session['user_id']:
            return {"error":"unauthorized"}, 401
        else:
            new_recipe = Recipe(
                title = json['title'],
                instructions = json['instructions'],
                minutes_to_complete = json['minutes_to_complete'],
                user_id = session['user_id'],
            )
            db.session.add(new_recipe)
            try:    
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                return {"error":"unprocessable entity"}, 422
            return new_recipe.to_dict(), 201

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
