#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        try:
            user = User(
                username=data['username'],
                password_hash=data['password'],
                image_url=data.get('image_url', ''),
                bio=data.get('bio', '')
            )
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return jsonify(id=user.id, username=user.username, image_url=user.image_url, bio=user.bio), 201
        except Exception as e:
            return jsonify(error=str(e)), 422


class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                return jsonify(id=user.id, username=user.username, image_url=user.image_url, bio=user.bio), 200
            return jsonify(error="User not found"), 401
        return jsonify(error="Unauthorized"), 401


class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify(error="Missing username or password"), 400

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            return jsonify(id=user.id, username=user.username, image_url=user.image_url, bio=user.bio), 200
        return jsonify(error="Unauthorized"), 401

class Logout(Resource):
    def delete(self):
        user_id = session.get('user_id')
        if user_id:
            session.pop('user_id', None)
            return jsonify(message="Logged out"), 204
        return jsonify(error="Unauthorized"), 401

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            recipes = Recipe.query.all()
            recipes_data = [
                {
                    "id": recipe.id,
                    "title": recipe.title,
                    "instructions": recipe.instructions,
                    "minutes_to_complete": recipe.minutes_to_complete,
                    "user": {
                        "id": recipe.user.id,
                        "username": recipe.user.username,
                        "image_url": recipe.user.image_url,
                        "bio": recipe.user.bio
                    }
                } for recipe in recipes
            ]
            return jsonify(recipes_data), 200
        return jsonify(error="Unauthorized"), 401

    def post(self):
        user_id = session.get('user_id')
        if user_id:
            data = request.get_json()
            try:
                recipe = Recipe(
                    title=data['title'],
                    instructions=data['instructions'],
                    minutes_to_complete=data['minutes_to_complete'],
                    user_id=user_id
                )
                db.session.add(recipe)
                db.session.commit()
                return jsonify(
                    id=recipe.id,
                    title=recipe.title,
                    instructions=recipe.instructions,
                    minutes_to_complete=recipe.minutes_to_complete,
                    user={
                        "id": recipe.user.id,
                        "username": recipe.user.username,
                        "image_url": recipe.user.image_url,
                        "bio": recipe.user.bio
                    }
                ), 201
            except Exception as e:
                return jsonify(error=str(e)), 422
        return jsonify(error="Unauthorized"), 401


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', methods=['DELETE']) 
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)