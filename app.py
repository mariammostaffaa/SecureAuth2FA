from flask import Flask, request, jsonify, send_file
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import pyotp
import qrcode
import io
import base64
import mysql.connector
import qrcode
from flask import send_file
import io

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'c20c04b5b002e401a9c8c1058d8096330cdff88259f71c493c9bf8741822b665'  

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Database Connection
db = mysql.connector.connect(
    host='localhost',
    user='root',
    password='root',
    database='auth_db'
)
cursor = db.cursor()

#1. User Registration
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        # Check if the username already exists
        cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            return jsonify({"message": "Username already exists. Please choose another one."}), 400

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        twofa_secret = pyotp.random_base32()

        # Insert new user
        cursor.execute("INSERT INTO users (username, password, twofa_secret) VALUES (%s, %s, %s)", 
                       (username, hashed_password, twofa_secret))
        db.commit()

        return jsonify({"message": "User registered successfully!"}), 201

    except Exception as e:
        print("❌ Registration Error:", e)
        return jsonify({"message": "Internal Server Error"}), 500


# 2. User Login (Generate QR Code for 2FA)
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # Fetch user details
    cursor.execute("SELECT password, twofa_secret FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if not user or not bcrypt.check_password_hash(user[0], password):  
        return jsonify({"message": "Invalid username or password"}), 401

    # Generate QR Code for 2FA
    twofa_secret = user[1]
    otp_uri = pyotp.totp.TOTP(twofa_secret).provisioning_uri(username, issuer_name="SecureApp")
    qr = qrcode.make(otp_uri)

    # Convert QR Code to an image file and send it directly
    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)

    return send_file(img_io, mimetype='image/png')

if __name__ == '__main__':
    app.run(debug=True)

# 3. Verify 2FA and Generate JWT Token
@app.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    data = request.json
    username = data.get('username')
    code = data.get('code')

    cursor.execute("SELECT twofa_secret FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    
    if not user or not pyotp.TOTP(user[0]).verify(code):
        return jsonify({"message": "Invalid 2FA code"}), 400

    # Generate JWT Token
    token = create_access_token(identity=username)
    return jsonify({"message": "2FA successful!", "token": token})

# 4. CRUD Operations on Products (Protected Routes)
@app.route('/products', methods=['POST'])
@jwt_required()
def add_product():
    data = request.json
    current_user = get_jwt_identity()

    cursor.execute("INSERT INTO products (name, description, price, quantity) VALUES (%s, %s, %s, %s)",
                   (data['name'], data['description'], data['price'], data['quantity']))
    db.commit()

    return jsonify({"message": f"Product added by {current_user}!"})

@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    return jsonify({"products": products})

@app.route('/products/<int:product_id>', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    data = request.json
    cursor.execute("UPDATE products SET name=%s, description=%s, price=%s, quantity=%s WHERE id=%s",
                   (data['name'], data['description'], data['price'], data['quantity'], product_id))
    db.commit()

    return jsonify({"message": "Product updated!"})

@app.route('/products/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    cursor.execute("DELETE FROM products WHERE id=%s", (product_id,))
    db.commit()
    return jsonify({"message": "Product deleted!"})

if __name__ == '__main__':
    app.run(debug=True)
