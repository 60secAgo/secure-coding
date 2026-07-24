import os
import re
import time
import uuid
import sqlite3
import logging
import secrets
from functools import wraps
from collections import defaultdict, deque
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, g, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room, disconnect

# ---------------------------------------------------------------------------
# 기본 설정
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'market.db')
SECRET_KEY_FILE = os.path.join(BASE_DIR, '.secret_key')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def _load_or_create_secret_key():
    """서버 재시작 시에도 세션이 유지되도록 비밀키를 파일에 보관.
    (단, 이 파일은 .gitignore 에 포함되어 저장소에 커밋되지 않아야 함)"""
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, 'r') as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, 'w') as f:
        f.write(key)
    return key


app = Flask(__name__)
app.config['SECRET_KEY'] = _load_or_create_secret_key()

# 세션 쿠키 보안 설정
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,          # JS에서 쿠키 접근 불가 (XSS로 인한 세션 탈취 완화)
    SESSION_COOKIE_SAMESITE='Lax',         # CSRF 위험 완화
    SESSION_COOKIE_SECURE=os.environ.get('FLASK_ENV') == 'production',  # HTTPS 환경에서만 True
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,  # 업로드 요청 본문 크기 제한(과대 업로드 방지, 5MB)
)

DEBUG_MODE = os.environ.get('FLASK_DEBUG', '0') == '1'

logging.basicConfig(
    filename=os.path.join(BASE_DIR, 'app.log'),
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)

# cors_allowed_origins를 지정하지 않으면 Flask-SocketIO는 기본적으로 "동일 출처(same-origin)"만
# 허용한다. 이는 교차 사이트 웹소켓 하이재킹(CSWSH)을 막으면서도 정상적인 브라우저 연결은 허용한다.
# (빈 리스트 []를 지정하면 Origin 헤더가 있는 모든 요청이 거부되어 채팅이 동작하지 않으므로 사용하지 않는다.)
socketio = SocketIO(app)

# ---------------------------------------------------------------------------
# 상수 / 정책 값
# ---------------------------------------------------------------------------
USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,20}$')
PASSWORD_RE = re.compile(r'^(?=.*[A-Za-z])(?=.*\d).{8,64}$')

MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCK_MINUTES = 5

PRODUCT_REPORT_THRESHOLD = 3   # 이 횟수 이상 신고되면 상품 자동 차단
USER_REPORT_THRESHOLD = 3      # 이 횟수 이상 신고되면 사용자 자동 휴면 전환

MAX_TITLE_LEN = 100
MAX_DESC_LEN = 2000
MAX_BIO_LEN = 500
MAX_REASON_LEN = 500
MAX_CHAT_LEN = 500
MAX_PRICE = 100_000_000
MAX_TRANSFER = 10_000_000

# 상품 이미지 업로드 정책
ALLOWED_IMAGE_EXT = {'png', 'jpg', 'jpeg', 'gif'}
MAX_IMAGE_BYTES = 5 * 1024 * 1024  # 5MB

DEFAULT_ADMIN_USERNAME = 'admin'
# 관리자 비밀번호는 소스코드에 하드코딩하지 않는다.
# 환경변수 ADMIN_PASSWORD가 있으면 사용하고, 없으면 최초 실행 시 무작위로 생성하여 콘솔에 1회 출력한다.

STARTING_BALANCE = 10000

# 채팅 rate limit: 사용자당 WINDOW 초 동안 MAX_MSG 개 메시지만 허용
CHAT_RATE_WINDOW = 10
CHAT_RATE_MAX_MSG = 5
_chat_history = defaultdict(deque)  # user_id -> deque[timestamp]


# ---------------------------------------------------------------------------
# 데이터베이스
# ---------------------------------------------------------------------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys = ON')
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                bio TEXT DEFAULT '',
                role TEXT NOT NULL DEFAULT 'user',        -- 'user' | 'admin'
                status TEXT NOT NULL DEFAULT 'active',     -- 'active' | 'dormant' | 'banned'
                balance INTEGER NOT NULL DEFAULT 0,
                report_count INTEGER NOT NULL DEFAULT 0,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                lock_until TEXT,
                created_at TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price INTEGER NOT NULL,
                seller_id TEXT NOT NULL,
                image_filename TEXT,
                status TEXT NOT NULL DEFAULT 'active',     -- 'active' | 'blocked'
                report_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (seller_id) REFERENCES user (id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_type TEXT NOT NULL,                 -- 'user' | 'product'
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(reporter_id, target_type, target_id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transfer (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                memo TEXT,
                created_at TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS message (
                id TEXT PRIMARY KEY,
                room TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        db.commit()

        # 최초 실행 시 기본 관리자 계정 생성
        cursor.execute("SELECT id FROM user WHERE username = ?", (DEFAULT_ADMIN_USERNAME,))
        if cursor.fetchone() is None:
            admin_password = os.environ.get('ADMIN_PASSWORD')
            generated = False
            if not admin_password:
                # 하드코딩 대신 무작위 비밀번호를 생성한다.
                admin_password = secrets.token_urlsafe(12)
                generated = True
            cursor.execute(
                "INSERT INTO user (id, username, password_hash, bio, role, status, balance, created_at) "
                "VALUES (?, ?, ?, ?, 'admin', 'active', 0, ?)",
                (str(uuid.uuid4()), DEFAULT_ADMIN_USERNAME,
                 generate_password_hash(admin_password), '관리자 계정', datetime.utcnow().isoformat())
            )
            db.commit()
            if generated:
                # 최초 1회만 콘솔에 출력된다. 로그인 후 즉시 변경할 것.
                print('=' * 60)
                print(' 초기 관리자 계정이 생성되었습니다.')
                print(f'   아이디  : {DEFAULT_ADMIN_USERNAME}')
                print(f'   비밀번호: {admin_password}')
                print(' (이 비밀번호는 지금만 표시됩니다. 로그인 후 반드시 변경하세요.)')
                print('=' * 60)


# ---------------------------------------------------------------------------
# CSRF 보호
# ---------------------------------------------------------------------------
def get_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']


app.jinja_env.globals['csrf_token'] = get_csrf_token


def validate_csrf():
    token = session.get('csrf_token')
    form_token = request.form.get('csrf_token')
    if not token or not form_token or not secrets.compare_digest(token, form_token):
        abort(400)


# ---------------------------------------------------------------------------
# 인증/인가 헬퍼
# ---------------------------------------------------------------------------
def current_user():
    if 'user_id' not in session:
        return None
    db = get_db()
    return db.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],)).fetchone()


app.jinja_env.globals['current_user'] = current_user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        user = current_user()
        if user is None or user['status'] != 'active':
            session.clear()
            flash('계정을 사용할 수 없습니다. 관리자에게 문의하세요.')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None or user['role'] != 'admin':
            abort(403)
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# 입력 검증 헬퍼
# ---------------------------------------------------------------------------
def is_valid_username(username):
    return bool(username) and bool(USERNAME_RE.match(username))


def is_valid_password(password):
    return bool(password) and bool(PASSWORD_RE.match(password))


def parse_positive_int(value, max_value):
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if n <= 0 or n > max_value:
        return None
    return n


def _detect_image_type(data):
    """파일 앞부분의 매직 넘버(시그니처)로 실제 이미지 형식을 판별한다.
    표준 라이브러리 버전에 의존하지 않도록 직접 구현했다.
    반환: 'png' | 'jpg' | 'gif' | None
    """
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        return 'png'
    if data[:3] == b'\xff\xd8\xff':
        return 'jpg'
    if data[:6] in (b'GIF87a', b'GIF89a'):
        return 'gif'
    return None


def save_product_image(file_storage):
    """상품 이미지를 검증 후 저장한다.
    - 파일이 없으면 None 반환(이미지 없음, 허용)
    - 형식/크기 위반 시 'INVALID' 반환
    - 성공 시 저장된 파일명 반환

    보안 처리:
    - 확장자 화이트리스트 검사
    - 파일 시그니처(매직 넘버)를 확인하여 위장된 파일 차단
    - 사용자가 준 파일명을 신뢰하지 않고 UUID 기반 새 파일명 사용(경로 조작/덮어쓰기 방지)
    """
    if not file_storage or not file_storage.filename:
        return None
    name = file_storage.filename
    ext = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
    if ext not in ALLOWED_IMAGE_EXT:
        return 'INVALID'
    data = file_storage.read()
    if not data or len(data) > MAX_IMAGE_BYTES:
        return 'INVALID'
    kind = _detect_image_type(data)   # 실제 이미지 형식 확인
    if kind is None:
        return 'INVALID'
    fname = f"{uuid.uuid4().hex}.{kind}"
    with open(os.path.join(UPLOAD_FOLDER, fname), 'wb') as f:
        f.write(data)
    return fname


# ---------------------------------------------------------------------------
# 보안 헤더 / 에러 핸들러
# ---------------------------------------------------------------------------
@app.after_request
def set_secure_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws: wss:; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'"
    )
    return response


@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', code=400, message='잘못된 요청입니다.'), 400


@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, message='접근 권한이 없습니다.'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message='페이지를 찾을 수 없습니다.'), 404


@app.errorhandler(413)
def payload_too_large(e):
    return render_template('error.html', code=413, message='업로드 용량이 너무 큽니다(최대 5MB).'), 413


@app.errorhandler(500)
def server_error(e):
    logging.exception('Internal server error')
    return render_template('error.html', code=500, message='서버 내부 오류가 발생했습니다.'), 500


# ---------------------------------------------------------------------------
# 기본 라우트
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        validate_csrf()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not is_valid_username(username):
            flash('사용자명은 영문/숫자/밑줄 3~20자여야 합니다.')
            return redirect(url_for('register'))
        if not is_valid_password(password):
            flash('비밀번호는 8자 이상이며 영문과 숫자를 포함해야 합니다.')
            return redirect(url_for('register'))
        if password != confirm:
            flash('비밀번호 확인이 일치하지 않습니다.')
            return redirect(url_for('register'))

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO user (id, username, password_hash, bio, role, status, balance, created_at) "
            "VALUES (?, ?, ?, '', 'user', 'active', ?, ?)",
            (user_id, username, generate_password_hash(password), STARTING_BALANCE, datetime.utcnow().isoformat())
        )
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')


# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        validate_csrf()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        # 사용자 존재 여부와 무관하게 동일한 오류 메시지를 반환하여 계정 존재 여부 노출 방지
        generic_error = '아이디 또는 비밀번호가 올바르지 않습니다.'

        if user is None:
            # 계정 존재 여부에 따른 응답 시간 차이(타이밍 공격을 통한 계정 열거)를 줄이기 위해
            # 존재하지 않는 사용자에 대해서도 더미 해시 비교를 수행한다.
            check_password_hash(
                'pbkdf2:sha256:600000$dummy$0000000000000000000000000000000000000000000000000000000000000000',
                password
            )
            flash(generic_error)
            return redirect(url_for('login'))

        if user['lock_until']:
            lock_until = datetime.fromisoformat(user['lock_until'])
            if datetime.utcnow() < lock_until:
                flash('로그인 시도 횟수를 초과하여 계정이 잠시 잠겼습니다. 잠시 후 다시 시도하세요.')
                return redirect(url_for('login'))

        if not check_password_hash(user['password_hash'], password):
            attempts = user['failed_attempts'] + 1
            lock_until = None
            if attempts >= MAX_LOGIN_ATTEMPTS:
                lock_until = (datetime.utcnow() + timedelta(minutes=LOGIN_LOCK_MINUTES)).isoformat()
                attempts = 0
            cursor.execute(
                "UPDATE user SET failed_attempts = ?, lock_until = ? WHERE id = ?",
                (attempts, lock_until, user['id'])
            )
            db.commit()
            flash(generic_error)
            return redirect(url_for('login'))

        if user['status'] == 'banned':
            flash('차단된 계정입니다. 관리자에게 문의하세요.')
            return redirect(url_for('login'))
        if user['status'] == 'dormant':
            flash('휴면 계정입니다. 관리자에게 문의하세요.')
            return redirect(url_for('login'))

        # 로그인 성공: 실패 카운터 초기화, 세션 고정 공격 방지를 위해 세션 재발급
        cursor.execute(
            "UPDATE user SET failed_attempts = 0, lock_until = NULL WHERE id = ?", (user['id'],)
        )
        db.commit()
        session.clear()
        session['user_id'] = user['id']
        session.permanent = True
        flash('로그인 성공!')
        return redirect(url_for('dashboard'))
    return render_template('login.html')


# 로그아웃
@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))


# 대시보드: 사용자 정보와 상품 리스트 (검색 지원)
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    query = request.args.get('q', '').strip()
    user = current_user()

    if query:
        if len(query) > 100:
            query = query[:100]
        # LIKE 메타문자(%, _, \)를 이스케이프하여 사용자가 입력한 문자를 리터럴로 검색한다.
        escaped = query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        like = f"%{escaped}%"
        products = db.execute(
            "SELECT * FROM product WHERE status = 'active' AND (title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\') "
            "ORDER BY created_at DESC",
            (like, like)
        ).fetchall()
    else:
        products = db.execute(
            "SELECT * FROM product WHERE status = 'active' ORDER BY created_at DESC"
        ).fetchall()

    return render_template('dashboard.html', products=products, user=user, query=query)


# 프로필 페이지: bio / 비밀번호 업데이트
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    user = current_user()
    if request.method == 'POST':
        validate_csrf()
        form_type = request.form.get('form_type')

        if form_type == 'bio':
            bio = request.form.get('bio', '')
            if len(bio) > MAX_BIO_LEN:
                flash(f'소개글은 {MAX_BIO_LEN}자를 넘을 수 없습니다.')
                return redirect(url_for('profile'))
            db.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, user['id']))
            db.commit()
            flash('프로필이 업데이트되었습니다.')

        elif form_type == 'password':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')

            if not check_password_hash(user['password_hash'], current_password):
                flash('현재 비밀번호가 일치하지 않습니다.')
                return redirect(url_for('profile'))
            if not is_valid_password(new_password):
                flash('새 비밀번호는 8자 이상이며 영문과 숫자를 포함해야 합니다.')
                return redirect(url_for('profile'))
            if new_password != confirm_password:
                flash('새 비밀번호 확인이 일치하지 않습니다.')
                return redirect(url_for('profile'))

            db.execute(
                "UPDATE user SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new_password), user['id'])
            )
            db.commit()
            flash('비밀번호가 변경되었습니다.')

        return redirect(url_for('profile'))

    # 내가 등록한 상품 목록(등록 상품 관리)
    my_products = db.execute(
        "SELECT * FROM product WHERE seller_id = ? ORDER BY created_at DESC",
        (user['id'],)
    ).fetchall()
    return render_template('profile.html', user=user, my_products=my_products)


# 다른 사용자 프로필 조회 (사용자 조회 기능)
@app.route('/user/<username>')
@login_required
def view_user(username):
    db = get_db()
    profile_user = db.execute("SELECT * FROM user WHERE username = ?", (username,)).fetchone()
    if profile_user is None:
        abort(404)
    # 활성 상품만 공개
    products = db.execute(
        "SELECT * FROM product WHERE seller_id = ? AND status = 'active' ORDER BY created_at DESC",
        (profile_user['id'],)
    ).fetchall()
    me = current_user()
    is_me = (profile_user['id'] == me['id'])
    return render_template('user_profile.html', profile_user=profile_user,
                           products=products, is_me=is_me)


# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        validate_csrf()
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        price = parse_positive_int(request.form.get('price', ''), MAX_PRICE)

        if not title or len(title) > MAX_TITLE_LEN:
            flash(f'제목은 1~{MAX_TITLE_LEN}자 이내로 입력하세요.')
            return redirect(url_for('new_product'))
        if not description or len(description) > MAX_DESC_LEN:
            flash(f'설명은 1~{MAX_DESC_LEN}자 이내로 입력하세요.')
            return redirect(url_for('new_product'))
        if price is None:
            flash(f'가격은 1~{MAX_PRICE} 사이의 숫자여야 합니다.')
            return redirect(url_for('new_product'))

        image_filename = save_product_image(request.files.get('image'))
        if image_filename == 'INVALID':
            flash('이미지는 png/jpg/gif 형식, 5MB 이하만 업로드할 수 있습니다.')
            return redirect(url_for('new_product'))

        db = get_db()
        product_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO product (id, title, description, price, seller_id, image_filename, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'active', ?)",
            (product_id, title, description, price, session['user_id'], image_filename,
             datetime.utcnow().isoformat())
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')


# 상품 상세보기
@app.route('/product/<product_id>')
@login_required
def view_product(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM product WHERE id = ?", (product_id,)).fetchone()
    if not product:
        abort(404)

    user = current_user()
    is_owner = product['seller_id'] == user['id']
    if product['status'] == 'blocked' and not is_owner and user['role'] != 'admin':
        abort(404)

    seller = db.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],)).fetchone()
    is_admin = user['role'] == 'admin'
    return render_template('view_product.html', product=product, seller=seller,
                           is_owner=is_owner, is_admin=is_admin)


# 상품 수정 (소유자만 가능)
@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM product WHERE id = ?", (product_id,)).fetchone()
    if not product:
        abort(404)

    user = current_user()
    # 소유자 확인: 소유자가 아니면 수정 불가 (관리자는 관리자 페이지의 상태변경만 허용)
    if product['seller_id'] != user['id']:
        abort(403)

    if request.method == 'POST':
        validate_csrf()
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        price = parse_positive_int(request.form.get('price', ''), MAX_PRICE)

        if not title or len(title) > MAX_TITLE_LEN:
            flash(f'제목은 1~{MAX_TITLE_LEN}자 이내로 입력하세요.')
            return redirect(url_for('edit_product', product_id=product_id))
        if not description or len(description) > MAX_DESC_LEN:
            flash(f'설명은 1~{MAX_DESC_LEN}자 이내로 입력하세요.')
            return redirect(url_for('edit_product', product_id=product_id))
        if price is None:
            flash(f'가격은 1~{MAX_PRICE} 사이의 숫자여야 합니다.')
            return redirect(url_for('edit_product', product_id=product_id))

        # 새 이미지가 업로드된 경우에만 교체한다.
        new_image = save_product_image(request.files.get('image'))
        if new_image == 'INVALID':
            flash('이미지는 png/jpg/gif 형식, 5MB 이하만 업로드할 수 있습니다.')
            return redirect(url_for('edit_product', product_id=product_id))

        if new_image:
            # 기존 이미지 파일 삭제(디스크 정리)
            old = product['image_filename']
            db.execute(
                "UPDATE product SET title = ?, description = ?, price = ?, image_filename = ? "
                "WHERE id = ? AND seller_id = ?",
                (title, description, price, new_image, product_id, user['id'])
            )
            if old:
                try:
                    os.remove(os.path.join(UPLOAD_FOLDER, os.path.basename(old)))
                except OSError:
                    pass
        else:
            db.execute(
                "UPDATE product SET title = ?, description = ?, price = ? WHERE id = ? AND seller_id = ?",
                (title, description, price, product_id, user['id'])
            )
        db.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    return render_template('edit_product.html', product=product)


# 상품 삭제 (소유자 또는 관리자)
@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    validate_csrf()
    db = get_db()
    product = db.execute("SELECT * FROM product WHERE id = ?", (product_id,)).fetchone()
    if not product:
        abort(404)

    user = current_user()
    # 소유자 확인: 소유자 또는 관리자만 삭제 가능
    if product['seller_id'] != user['id'] and user['role'] != 'admin':
        abort(403)

    db.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    logging.info('product deleted: %s by %s', product_id, user['id'])
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))


# 신고하기 (사용자 또는 상품)
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    db = get_db()
    if request.method == 'POST':
        validate_csrf()
        target_type = request.form.get('target_type', '')
        target_id = request.form.get('target_id', '').strip()
        reason = request.form.get('reason', '').strip()

        if target_type not in ('user', 'product'):
            flash('잘못된 신고 대상 유형입니다.')
            return redirect(url_for('report'))
        if not reason or len(reason) > MAX_REASON_LEN:
            flash(f'신고 사유는 1~{MAX_REASON_LEN}자 이내로 입력하세요.')
            return redirect(url_for('report'))

        if target_type == 'user':
            target = db.execute("SELECT * FROM user WHERE id = ?", (target_id,)).fetchone()
        else:
            target = db.execute("SELECT * FROM product WHERE id = ?", (target_id,)).fetchone()

        if target is None:
            flash('신고 대상을 찾을 수 없습니다.')
            return redirect(url_for('report'))

        if target_type == 'user' and target_id == session['user_id']:
            flash('본인을 신고할 수 없습니다.')
            return redirect(url_for('report'))
        if target_type == 'product' and target['seller_id'] == session['user_id']:
            flash('본인의 상품은 신고할 수 없습니다.')
            return redirect(url_for('report'))

        cursor = db.cursor()
        try:
            cursor.execute(
                "INSERT INTO report (id, reporter_id, target_type, target_id, reason, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), session['user_id'], target_type, target_id, reason, datetime.utcnow().isoformat())
            )
        except sqlite3.IntegrityError:
            flash('이미 신고한 대상입니다.')
            return redirect(url_for('report'))

        # 신고 누적 횟수(서로 다른 신고자 기준) 확인 후 임계치 초과 시 자동 조치
        count = cursor.execute(
            "SELECT COUNT(DISTINCT reporter_id) AS cnt FROM report WHERE target_type = ? AND target_id = ?",
            (target_type, target_id)
        ).fetchone()['cnt']

        if target_type == 'product':
            cursor.execute("UPDATE product SET report_count = ? WHERE id = ?", (count, target_id))
            if count >= PRODUCT_REPORT_THRESHOLD:
                cursor.execute("UPDATE product SET status = 'blocked' WHERE id = ?", (target_id,))
        else:
            cursor.execute("UPDATE user SET report_count = ? WHERE id = ?", (count, target_id))
            if count >= USER_REPORT_THRESHOLD:
                cursor.execute("UPDATE user SET status = 'dormant' WHERE id = ?", (target_id,))

        db.commit()
        logging.info('report created: reporter=%s target_type=%s target=%s',
                      session['user_id'], target_type, target_id)
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')


# 송금
@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    db = get_db()
    user = current_user()
    if request.method == 'POST':
        validate_csrf()
        receiver_username = request.form.get('receiver', '').strip()
        amount = parse_positive_int(request.form.get('amount', ''), MAX_TRANSFER)
        password = request.form.get('password', '')
        memo = request.form.get('memo', '').strip()[:200]

        if not check_password_hash(user['password_hash'], password):
            flash('비밀번호가 일치하지 않아 송금이 취소되었습니다.')
            return redirect(url_for('transfer'))

        if amount is None:
            flash(f'송금액은 1~{MAX_TRANSFER} 사이의 숫자여야 합니다.')
            return redirect(url_for('transfer'))

        receiver = db.execute(
            "SELECT * FROM user WHERE username = ?", (receiver_username,)
        ).fetchone()
        if receiver is None or receiver['status'] != 'active':
            flash('송금 대상 사용자를 찾을 수 없습니다.')
            return redirect(url_for('transfer'))
        if receiver['id'] == user['id']:
            flash('본인에게 송금할 수 없습니다.')
            return redirect(url_for('transfer'))
        if amount > user['balance']:
            flash('잔액이 부족합니다.')
            return redirect(url_for('transfer'))

        try:
            cursor = db.cursor()
            # 조건부 UPDATE(WHERE balance >= ?)로 잔액 검증과 차감을 하나의 원자적 SQL 문으로 처리하여
            # 이중 송금/잔액 음수화(레이스 컨디션)를 방지한다. (sqlite3는 기본적으로 이 UPDATE 문 실행 시
            # 묵시적 트랜잭션을 시작하므로 별도의 수동 BEGIN이 필요하지 않다.)
            cursor.execute(
                "UPDATE user SET balance = balance - ? WHERE id = ? AND balance >= ?",
                (amount, user['id'], amount)
            )
            if cursor.rowcount == 0:
                db.rollback()
                flash('잔액이 부족합니다.')
                return redirect(url_for('transfer'))
            cursor.execute(
                "UPDATE user SET balance = balance + ? WHERE id = ?",
                (amount, receiver['id'])
            )
            cursor.execute(
                "INSERT INTO transfer (id, sender_id, receiver_id, amount, memo, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), user['id'], receiver['id'], amount, memo, datetime.utcnow().isoformat())
            )
            db.commit()
        except Exception:
            db.rollback()
            logging.exception('transfer failed')
            flash('송금 처리 중 오류가 발생했습니다.')
            return redirect(url_for('transfer'))

        logging.info('transfer: %s -> %s amount=%s', user['id'], receiver['id'], amount)
        flash(f'{receiver_username}님에게 {amount}원을 송금했습니다.')
        return redirect(url_for('transfer'))

    history = db.execute(
        "SELECT t.*, su.username AS sender_name, ru.username AS receiver_name "
        "FROM transfer t "
        "JOIN user su ON t.sender_id = su.id "
        "JOIN user ru ON t.receiver_id = ru.id "
        "WHERE t.sender_id = ? OR t.receiver_id = ? "
        "ORDER BY t.created_at DESC LIMIT 20",
        (user['id'], user['id'])
    ).fetchall()
    return render_template('transfer.html', user=user, history=history)


# 1:1 채팅
@app.route('/chat/<other_username>')
@login_required
def chat_room(other_username):
    db = get_db()
    other = db.execute("SELECT * FROM user WHERE username = ?", (other_username,)).fetchone()
    if other is None:
        abort(404)
    me = current_user()
    if other['id'] == me['id']:
        flash('본인과는 채팅할 수 없습니다.')
        return redirect(url_for('dashboard'))

    room = '_'.join(sorted([me['id'], other['id']]))
    history = db.execute(
        "SELECT m.*, u.username FROM message m JOIN user u ON m.sender_id = u.id "
        "WHERE m.room = ? ORDER BY m.created_at ASC LIMIT 100",
        (room,)
    ).fetchall()
    return render_template('chat_room.html', other=other, room=room, me=me, history=history)


# ---------------------------------------------------------------------------
# 관리자 페이지
# ---------------------------------------------------------------------------
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    db = get_db()
    users = db.execute("SELECT * FROM user ORDER BY created_at DESC").fetchall()
    products = db.execute("SELECT * FROM product ORDER BY created_at DESC").fetchall()
    reports = db.execute(
        "SELECT r.*, ru.username AS reporter_name FROM report r "
        "JOIN user ru ON r.reporter_id = ru.id ORDER BY r.created_at DESC LIMIT 100"
    ).fetchall()
    return render_template('admin.html', users=users, products=products, reports=reports)


@app.route('/admin/user/<user_id>/status', methods=['POST'])
@login_required
@admin_required
def admin_update_user_status(user_id):
    validate_csrf()
    new_status = request.form.get('status')
    if new_status not in ('active', 'dormant', 'banned'):
        abort(400)
    db = get_db()
    target = db.execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        abort(404)
    # 관리자 계정은 상태 변경 대상에서 제외한다(자기 자신 또는 다른 관리자 잠금 방지).
    if target['role'] == 'admin':
        flash('관리자 계정의 상태는 변경할 수 없습니다.')
        return redirect(url_for('admin_dashboard'))
    db.execute("UPDATE user SET status = ? WHERE id = ?", (new_status, user_id))
    db.commit()
    logging.info('admin %s set user %s status=%s', session['user_id'], user_id, new_status)
    flash('사용자 상태가 변경되었습니다.')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/product/<product_id>/status', methods=['POST'])
@login_required
@admin_required
def admin_update_product_status(product_id):
    validate_csrf()
    new_status = request.form.get('status')
    if new_status not in ('active', 'blocked'):
        abort(400)
    db = get_db()
    db.execute("UPDATE product SET status = ? WHERE id = ?", (new_status, product_id))
    db.commit()
    logging.info('admin %s set product %s status=%s', session['user_id'], product_id, new_status)
    flash('상품 상태가 변경되었습니다.')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/report/<report_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_report(report_id):
    validate_csrf()
    db = get_db()
    db.execute("DELETE FROM report WHERE id = ?", (report_id,))
    db.commit()
    flash('신고 내역이 삭제되었습니다.')
    return redirect(url_for('admin_dashboard'))


# ---------------------------------------------------------------------------
# Socket.IO: 실시간 채팅 (전체 채팅 + 1:1 채팅)
# ---------------------------------------------------------------------------
def _rate_limited(user_id):
    now = time.time()
    dq = _chat_history[user_id]
    while dq and now - dq[0] > CHAT_RATE_WINDOW:
        dq.popleft()
    if len(dq) >= CHAT_RATE_MAX_MSG:
        return True
    dq.append(now)
    return False


@socketio.on('connect')
def handle_connect():
    if 'user_id' not in session:
        disconnect()
        return False


@socketio.on('send_message')
def handle_send_message_event(data):
    if 'user_id' not in session:
        disconnect()
        return
    user = current_user()
    if user is None or user['status'] != 'active':
        disconnect()
        return
    if _rate_limited(user['id']):
        emit('error_message', {'message': '메시지를 너무 빠르게 보내고 있습니다.'})
        return

    message = str(data.get('message', ''))[:MAX_CHAT_LEN].strip()
    if not message:
        return
    emit('message', {
        'message_id': str(uuid.uuid4()),
        'username': user['username'],
        'message': message,
    }, broadcast=True)


@socketio.on('join_direct_room')
def handle_join_direct_room(data):
    if 'user_id' not in session:
        disconnect()
        return
    room = str(data.get('room', ''))
    parts = room.split('_')
    if session['user_id'] not in parts or len(parts) != 2:
        return  # 본인이 속하지 않은 방에는 참가할 수 없음
    join_room(room)


@socketio.on('send_direct_message')
def handle_send_direct_message(data):
    if 'user_id' not in session:
        disconnect()
        return
    user = current_user()
    if user is None or user['status'] != 'active':
        disconnect()
        return

    room = str(data.get('room', ''))
    parts = room.split('_')
    if user['id'] not in parts or len(parts) != 2:
        return

    if _rate_limited(user['id']):
        emit('error_message', {'message': '메시지를 너무 빠르게 보내고 있습니다.'}, room=room)
        return

    message = str(data.get('message', ''))[:MAX_CHAT_LEN].strip()
    if not message:
        return

    db = get_db()
    msg_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO message (id, room, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?)",
        (msg_id, room, user['id'], message, datetime.utcnow().isoformat())
    )
    db.commit()

    emit('direct_message', {
        'message_id': msg_id,
        'username': user['username'],
        'message': message,
    }, room=room)


if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=DEBUG_MODE, host='127.0.0.1', port=5000)
