from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import jwt
import datetime
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})
app.config['SECRET_KEY'] = 'your-secret-key'

# Конфиг БД
DB_CONFIG = {
    "dbname": "users",
    "user": "python",
    "password": "python",
    "host": "postgres",
    "port": "5432"
}

def get_db():
    """Получение соединения с БД"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        print(f"❌ Ошибка подключения к БД: {e}")
        return None

def init_db():
    """Создаёт таблицу users, если её нет"""
    conn = None
    try:
        conn = get_db()
        if conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(50) NOT NULL,
                        email VARCHAR(100) UNIQUE NOT NULL,
                        password VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                conn.commit()
            print("✅ Таблица 'users' готова")
        else:
            print("❌ Не удалось подключиться к БД для инициализации")
    except Exception as e:
        print(f"❌ Ошибка инициализации БД: {e}")
    finally:
        if conn:
            conn.close()

@app.route('/')
def health_check():
    """Проверка здоровья API"""
    return jsonify({
        'status': 'ok',
        'message': 'API is running',
        'timestamp': datetime.datetime.utcnow().isoformat()
    }), 200

@app.route('/api/health', methods=['GET'])
def api_health():
    """Проверка здоровья API для фронтенда"""
    try:
        conn = get_db()
        if conn:
            conn.close()
            return jsonify({
                'status': 'ok',
                'database': 'connected',
                'timestamp': datetime.datetime.utcnow().isoformat()
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'database': 'disconnected',
                'timestamp': datetime.datetime.utcnow().isoformat()
            }), 500
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.datetime.utcnow().isoformat()
        }), 500

@app.route('/api/register', methods=['POST', 'OPTIONS'])
def register():
    """Регистрация пользователя"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    
    conn = None
    try:
        data = request.get_json()
        
        # Валидация данных
        if not data or 'email' not in data or 'password' not in data or 'username' not in data:
            return jsonify({'error': 'Missing required fields'}), 400
        
        if len(data['password']) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        conn = get_db()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        with conn.cursor() as cur:
            # Проверяем, существует ли пользователь с таким email
            cur.execute(
                "SELECT id FROM users WHERE email = %s",
                (data['email'],)
            )
            if cur.fetchone():
                return jsonify({'error': 'User with this email already exists'}), 409
            
            hashed_pw = generate_password_hash(data['password'])
            cur.execute(
                """
                INSERT INTO users (username, email, password)
                VALUES (%s, %s, %s) RETURNING id, username, email
                """,
                (data['username'], data['email'], hashed_pw)
            )
            user_row = cur.fetchone()
            user_id = user_row[0]
            conn.commit()
            
            # Создаём токен
            payload = {
                'user_id': user_id,
                'username': user_row[1],
                'email': user_row[2],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
            }
            token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")
            
            # Если token в bytes, декодируем в строку
            if isinstance(token, bytes):
                token = token.decode('utf-8')
                
            return jsonify({
                'token': token,
                'user_id': user_id,
                'username': user_row[1],
                'email': user_row[2],
                'message': 'Registration successful'
            }), 201
            
    except psycopg2.IntegrityError as e:
        return jsonify({'error': 'Database integrity error', 'details': str(e)}), 400
    except Exception as e:
        print(f"❌ Ошибка регистрации: {e}")
        return jsonify({'error': 'Registration failed', 'details': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    """Аутентификация пользователя"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    
    conn = None
    try:
        data = request.get_json()
        
        # Валидация данных
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'error': 'Email and password are required'}), 400
        
        conn = get_db()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, username, email, password FROM users WHERE email = %s",
                (data['email'],)
            )
            user = cur.fetchone()
            
            if user and check_password_hash(user[3], data['password']):
                # Создаём токен
                payload = {
                    'user_id': user[0],
                    'username': user[1],
                    'email': user[2],
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
                }
                token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")
                
                # Если token в bytes, декодируем в строку
                if isinstance(token, bytes):
                    token = token.decode('utf-8')
                    
                return jsonify({
                    'token': token,
                    'user_id': user[0],
                    'username': user[1],
                    'email': user[2],
                    'message': 'Login successful'
                }), 200
                
            return jsonify({'error': 'Invalid email or password'}), 401
            
    except Exception as e:
        print(f"❌ Ошибка входа: {e}")
        return jsonify({'error': 'Login failed', 'details': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    print("🚀 Starting Flask server...")
    print("📊 Initializing database...")
    init_db()  # создаём таблицу при старте
    print("✅ Database initialized")
    print("🌐 Server running on http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)