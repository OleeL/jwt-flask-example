import datetime
from flask import Flask, request, jsonify
import jwt  # PyJWT
from dotenv import dotenv_values
envValues = dotenv_values(".env")
app = Flask(__name__)
app.config["SECRET_KEY"] = envValues.get("SECRET_KEY", "test123")
iss = "my-flask-app"

# Issue Access Token
def create_access_token(data, expires_in=15): # 15 minutes
    expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=expires_in)
    token = jwt.encode(
        {
            "data": data,
            "exp": expiration,
            "iss": iss
        },
        app.config['SECRET_KEY'],
        algorithm="HS256"
    )
    return token

# Issue Refresh Token (longer expiry)
def create_refresh_token(data, expires_in=1440): # 1440 minutes = 24 hours
    expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=expires_in)
    token = jwt.encode(
        {
            "data": data,
            "exp": expiration,
            "iss": iss
        },
        app.config['SECRET_KEY'],
        algorithm="HS256"
    )
    return token

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    # This is a mock check; in practice, validate with a database
    if username == "test" and password == "pass":
        access_token = create_access_token({"username": username})
        refresh_token = create_refresh_token({"username": username})
        """
        We're just sending back this on the response body, ideally, you'd want
        to send this back as an http only cookie
        """
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token
        }), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route("/protected", methods=["GET"])
def protected():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Missing auth header"}), 401

    token = auth_header.split(" ")[1]  # Bearer <token>
    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return jsonify({"message": "Access granted", "user_data": decoded["data"]}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

@app.route("/refresh", methods=["POST"])
def refresh():
    refresh_token = request.json.get("refresh_token")
    if not refresh_token:
        return jsonify({"error": "Missing refresh token"}), 401

    try:
        decoded = jwt.decode(refresh_token, app.config['SECRET_KEY'], algorithms=["HS256"])
        # If we get here, refresh token is valid
        new_access_token = create_access_token({"username": decoded["data"]["username"]})
        return jsonify({"access_token": new_access_token}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid refresh token"}), 401

if __name__ == "__main__":
    app.run(debug=True, port=5999)