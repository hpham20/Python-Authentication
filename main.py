from flask import Flask, jsonify, request
from flask_cors import CORS
import mysql.connector
import hashlib
import json
import os
from dotenv import load_dotenv
import jwt
import requests

load_dotenv()
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
PUBLIC_KEY = os.getenv("PUBLIC_KEY")
GOOGLE_PUBLIC_KEY = os.getenv("GOOGLE_PUBLIC_KEY")

mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password=DATABASE_PASSWORD,
    database="python_capstone"
)

mycursor = mydb.cursor()
# mycursor.execute("SELECT * FROM users")
# rows = mycursor.fetchall()
# for row in rows:
#     print(row)

app = Flask(__name__)
CORS(app)

db = {
    1: {
        "name": "Henry",
        "email": "henry@email.com",
        "phoneNum": "1231231234",
        "username": "henpham",
        "password": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",

    },
}

def get_id_by_username(username):
    """
    Get User ID from given username, assuming the user exists
    """
    # SELECT * FROM users WHERE username column = username param
    for user_id in db:
        if (db[user_id].get("username") == username):
            return user_id
    return None

def username_exists(username):
    """
    Find username in database. Returns user if found, None if not
    """
    query = f"SELECT * FROM users WHERE username = \"{username}\""
    mycursor.execute(query)
    user = mycursor.fetchone()

    return user

def email_exists(email):
    """
    Find email in database. Returns user if found, None if not
    """
    query = f"SELECT * FROM users WHERE email = \"{email}\""
    mycursor.execute(query)
    user = mycursor.fetchone()

    return user

# GET USER (Test)
@app.get("/user/<user_id>")
def get_user(user_id):
    user_id = int(user_id)

    if (user_id in db):
        return jsonify(db[user_id]), 200
    else:
        return jsonify({"message": "User not found"}), 404


@app.post("/login")
def handle_login():
    """
    Handle user login. Receives login credentials from HTTP request.
    Conditions for successful login:
        Username exists in the database
        Username and password match

    Parameters:
        None (Uses JSON data from HTTP request)

    Returns:
        JSON response with success message if user logs in successfully
    """
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")
    # GET USER
    hashed_password = to_hashed(password)

    if (username_exists(username)):
        query = f"SELECT password FROM users WHERE username = \"{username}\""
        mycursor.execute(query)
        stored_password = mycursor.fetchone()[0]
        if stored_password == hashed_password:
            # Create Token using RS256
            token = jwt.encode(
                {"username": username}, 
                PRIVATE_KEY, 
                algorithm="RS256"
            )
            return jsonify({"message": f"Successful Login, {username}", "token": token, "user": username}), 200
    return jsonify({"message": "User or password is incorrect"}), 400


# Register User
@app.post("/register")
def handle_register():
    """
    Handle user registration. Receives registration data from HTTP POST request

    Parameters:
        None

    Returns:
        JSON response with success message if registration is successful and error message if
        the user already exists
    """
    data = request.get_json()

    name = data.get("name")
    email = data.get("email")
    phoneNum = data.get("phoneNum")
    username = data.get("username")
    password = data.get("password")

    # Check database to see if user already exists
    if (username_exists(username)):
        return jsonify({"message": "User already exists"}), 400
    
    if (email_exists(email)):
        return jsonify({"message": "Email already in use"}), 400

    # If user doesn't exist, add to database
    hashed_password = to_hashed(password)

    new_user_query = """
        INSERT INTO users
        (name, email, phoneNum, username, password) 
        VALUES (%s, %s, %s, %s, %s);
    """

    new_user_data = (name, email, phoneNum, username, hashed_password)
    mycursor.execute(new_user_query, new_user_data)
    mydb.commit()
    # newKey = max(db.keys()) + 1
    # db[newKey] = {
    #     "name": name,
    #     "email": email,
    #     "phoneNum": phoneNum,
    #     "username": username,
    #     "password": hashed_password,
    # }
    return jsonify({"message": f"Successfully registered {username}"}), 200

@app.post("/protected")
def test_authentication():
    """
    Handle user authentication based on the provided token.
    Extracts token from the request header, decodes it using Public Key and verifies it using RS256 algorithm.
    If successful, returns a JSON message welcoming the current user with a 200 status code.
    If decoding fails, returns a JSON message indicating authentication failure with a 401 status code.
    If no token is provided, returns a JSON message indicating no token was provided with a 401 status code.
    """
    header = request.headers.get("Authorization")

    if header:
        token = header.split(" ")[1]
        try:
            decoded = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
            current_user = decoded["username"]
            return jsonify({"message": f"Authentication successful. Welcome {current_user}"}), 200
        except:
            return jsonify({"message": "Authentication failed"}), 401
    else:
        return jsonify({"message": "No token provided"}), 401

@app.post("/google-login")
def google_login():
    try:
        data = request.get_json()
        google_jwt = data["token"]["credential"]
        response = requests.get("https://www.googleapis.com/oauth2/v3/certs")
        public_keys = response.json()
        # decoded = jwt.decode(google_jwt, public_keys, algorithms=["RS256"])
        decoded = jwt.decode(google_jwt, options={"verify_signature": False})

        email = decoded["email"]
        query = f"SELECT username FROM users WHERE email = \"{email}\""
        mycursor.execute(query)
        username = mycursor.fetchone()[0]

        # If username doesn't exist, use email as username for token
        if not username:
            username = email.split("@")[0]

        token = jwt.encode({"username": username}, PRIVATE_KEY, algorithm="RS256")
        return jsonify({"message": f"Authentication successful", "token": token, "user": username}), 200
    
    except:
        return jsonify({"message": "Authentication failed"}), 401

def print_db():
    """Print the contents of the hard-coded database"""
    print(json.dumps(db, indent=4))
        

def to_hashed(password):
    """Converts plaintext password into hashed version using SHA-256 algorithm"""
    password_bytes = password.encode("UTF-8")
    hash_object = hashlib.sha256(password_bytes)
    hashed_password = hash_object.hexdigest()

    return hashed_password


def print_menu():
    print("What would you like to do?")
    print("1. Login")
    print("2. Register")
    print("3. Quit")

    option = input()

    if (option == "1"):
        handle_login()
    elif (option == "2"):
        handle_register()
    else:
        print("Exited. Goodbye!")
        exit()


def main():
    app.run(debug=True)
    # while True:
    #     print_menu()
    # encoded = jwt.encode({"username": "henpham"}, PRIVATE_KEY, algorithm="RS256")
    # print(f"Token: {encoded}")

    # decoded = jwt.decode(encoded, PUBLIC_KEY, algorithms=["RS256"])
    # print(f"Decoded: {decoded}")


if __name__ == "__main__":
    main()