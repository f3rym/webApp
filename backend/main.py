from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import jwt
import datetime
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'your-secret-key'

# Конфиг БД
DB_CONFIG = {
    "dbname": "users",
    "user": "python",
    "password": "python",
    "host": "localhost"
}

def get_db():
    return psycopg2.connect(**DB_CONFIG)

def init_db():
    """Создаёт таблицу users, если её нет"""
    conn = None
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) NOT NULL,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL
                );
            """)
            conn.commit()
        print("✅ Таблица 'users' готова")
    except Exception as e:
        print(f"❌ Ошибка инициализации БД: {e}")
    finally:
        if conn:
            conn.close()

@app.route('/api/register', methods=['POST'])
def register():
    conn = None
    try:
        data = request.get_json()
        conn = get_db()
        with conn.cursor() as cur:
            hashed_pw = generate_password_hash(data['password'])
            cur.execute(
                "INSERT INTO users (username, email, password) VALUES (%s, %s, %s) RETURNING id",
                (data['username'], data['email'], hashed_pw)
            )
            user_id = cur.fetchone()[0]
            conn.commit()

            token = jwt.encode({
                'user_id': user_id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
            }, app.config['SECRET_KEY'], algorithm="HS256")

            return jsonify({'token': token, 'user_id': user_id}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    finally:
        if conn:
            conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    conn = None
    try:
        data = request.get_json()
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, password FROM users WHERE email = %s",
                (data['email'],)
            )
            user = cur.fetchone()
            if user and check_password_hash(user[1], data['password']):
                token = jwt.encode({
                    'user_id': user[0],
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
                }, app.config['SECRET_KEY'], algorithm="HS256")
                return jsonify({'token': token}), 200
            return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    init_db()  # создаём таблицу при старте
    app.run(host='0.0.0.0', port=5000)
