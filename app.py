import sqlite3
import uuid
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
DATABASE = 'market.db'
socketio = SocketIO(app)

# Flask-Login 설정
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_id, username, password, bio=None, is_admin=False, ban_until=None):
        self.id = user_id
        self.username = username
        self.password = password
        self.bio = bio
        self.is_admin = is_admin
        self.ban_until = ban_until

    def is_banned(self):
        if self.ban_until:
            return datetime.now() < datetime.fromisoformat(self.ban_until)
        return False

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    if user_data:
        return User(
            user_data['id'], 
            user_data['username'], 
            user_data['password'], 
            user_data['bio'],
            bool(user_data['is_admin']),
            user_data['ban_until']
        )
    return None

# 업로드 폴더가 없으면 생성
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성 (is_admin, ban_until 필드 추가)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                is_admin BOOLEAN DEFAULT 0,
                ban_until TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                image_path TEXT
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending'
            )
        """)
        db.commit()

        # 관리자 계정 생성
        cursor.execute("SELECT * FROM user WHERE username = 'admin'")
        if not cursor.fetchone():
            admin_id = str(uuid.uuid4())
            hashed_password = generate_password_hash('1234')
            cursor.execute(
                "INSERT INTO user (id, username, password, is_admin) VALUES (?, ?, ?, ?)",
                (admin_id, 'admin', hashed_password, 1)
            )
            db.commit()

# 가격 포맷팅 필터 추가
@app.template_filter('format_price')
def format_price(price):
    try:
        return "{:,}".format(int(price))
    except (ValueError, TypeError):
        return price

# 기본 라우트
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        hashed_password = generate_password_hash(password)
        cursor.execute("INSERT INTO user (id, username, password, is_admin) VALUES (?, ?, ?, 0)",
                       (user_id, username, hashed_password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user_data = cursor.fetchone()
        
        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data['id'], user_data['username'], user_data['password'], user_data['bio'], user_data['is_admin'], user_data['ban_until'])
            login_user(user)
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    logout_user()
    flash('로그아웃되었습니다.')
    return redirect(url_for('login'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    cursor = db.cursor()
    
    # 검색어 가져오기
    search_query = request.args.get('search', '')
    
    # 검색어가 있으면 검색 결과, 없으면 전체 상품 조회
    if search_query:
        cursor.execute("""
            SELECT p.*, u.username as seller_username 
            FROM product p 
            JOIN user u ON p.seller_id = u.id 
            WHERE p.title LIKE ?
        """, ('%' + search_query + '%',))
    else:
        cursor.execute("""
            SELECT p.*, u.username as seller_username 
            FROM product p 
            JOIN user u ON p.seller_id = u.id
        """)
    
    all_products = cursor.fetchall()
    return render_template('dashboard.html', 
                         products=all_products, 
                         search_query=search_query,
                         user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, current_user.id))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile', user_id=current_user.id))
    cursor.execute("SELECT * FROM user WHERE id = ?", (current_user.id,))
    user = cursor.fetchone()
    return render_template('edit_profile.html', user=user)

# 사용자 프로필 페이지
@app.route('/profile/<user_id>')
def profile(user_id):
    db = get_db()
    cursor = db.cursor()
    
    # 사용자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 사용자의 상품 목록 조회
    cursor.execute("SELECT * FROM product WHERE seller_id = ?", (user_id,))
    products = cursor.fetchall()
    
    return render_template('profile.html', user=user, products=products)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        
        # 이미지 파일 처리
        image = request.files.get('image')
        image_path = None
        if image and image.filename:
            filename = secure_filename(image.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            image.save(image_path)
            image_path = f"uploads/{unique_filename}"  # 웹에서 접근 가능한 경로로 저장

        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id, image_path) VALUES (?, ?, ?, ?, ?, ?)",
            (product_id, title, description, price, current_user.id, image_path)
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('product_detail.html', product=product, seller=seller)

# 상품 수정
@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 상품 정보 조회
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 판매자만 수정 가능
    if product['seller_id'] != session['user_id']:
        flash('상품을 수정할 권한이 없습니다.')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        
        # 이미지 파일 처리
        image = request.files.get('image')
        if image and image.filename:
            filename = secure_filename(image.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            image.save(image_path)
            image_path = f"uploads/{unique_filename}"  # 웹에서 접근 가능한 경로로 저장
            
            # 기존 이미지 삭제
            if product['image_path']:
                try:
                    os.remove(os.path.join('static', product['image_path']))
                except:
                    pass
            
            cursor.execute("UPDATE product SET title = ?, description = ?, price = ?, image_path = ? WHERE id = ?",
                          (title, description, price, image_path, product_id))
        else:
            cursor.execute("UPDATE product SET title = ?, description = ?, price = ? WHERE id = ?",
                          (title, description, price, product_id))
        
        db.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    
    return render_template('edit_product.html', product=product)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

# 상품 삭제
@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    # 상품 정보 조회
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 현재 로그인한 사용자와 상품 판매자가 일치하는지 확인
    if product['seller_id'] != current_user.id:
        flash('상품을 삭제할 권한이 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 이미지 파일 삭제
    if product['image_path']:
        try:
            os.remove(os.path.join('static', product['image_path']))
        except:
            pass
    
    # 상품 삭제
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # 현재 비밀번호 확인
    if not check_password_hash(current_user.password, current_password):
        flash('현재 비밀번호가 일치하지 않습니다.', 'error')
        return redirect(url_for('edit_profile'))
    
    # 새 비밀번호 확인
    if new_password != confirm_password:
        flash('새 비밀번호가 일치하지 않습니다.', 'error')
        return redirect(url_for('edit_profile'))
    
    # 비밀번호 길이 확인
    if len(new_password) < 8:
        flash('비밀번호는 최소 8자 이상이어야 합니다.', 'error')
        return redirect(url_for('edit_profile'))
    
    # 비밀번호 업데이트
    db = get_db()
    cursor = db.cursor()
    hashed_password = generate_password_hash(new_password)
    cursor.execute("UPDATE user SET password = ? WHERE id = ?", 
                  (hashed_password, current_user.id))
    db.commit()
    
    flash('비밀번호가 성공적으로 변경되었습니다.', 'success')
    return redirect(url_for('edit_profile'))

def reset_user_passwords():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 모든 사용자의 비밀번호를 'password123'으로 초기화
        default_password = generate_password_hash('password123')
        cursor.execute("UPDATE user SET password = ?", (default_password,))
        db.commit()
        print("모든 사용자의 비밀번호가 'password123'으로 초기화되었습니다.")

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('관리자만 접근할 수 있습니다.')
        return redirect(url_for('dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 신고 목록 조회
    cursor.execute("""
        SELECT r.*, u1.username as reporter_name, u2.username as target_name
        FROM report r
        JOIN user u1 ON r.reporter_id = u1.id
        JOIN user u2 ON r.target_id = u2.id
        ORDER BY r.created_at DESC
    """)
    reports = cursor.fetchall()
    
    # 사용자 목록 조회
    cursor.execute("SELECT * FROM user ORDER BY username")
    users = cursor.fetchall()
    
    return render_template('admin_dashboard.html', reports=reports, users=users)

@app.route('/admin/ban_user', methods=['POST'])
@login_required
def ban_user():
    if not current_user.is_admin:
        flash('관리자만 접근할 수 있습니다.')
        return redirect(url_for('dashboard'))
    
    user_id = request.form.get('user_id')
    ban_days = int(request.form.get('ban_days', 0))
    
    if ban_days == -1:  # 영구 정지
        ban_until = '9999-12-31'
    else:
        ban_until = (datetime.now() + timedelta(days=ban_days)).isoformat()
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET ban_until = ? WHERE id = ?", (ban_until, user_id))
    db.commit()
    
    flash('사용자가 정지되었습니다.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/unban_user', methods=['POST'])
@login_required
def unban_user():
    if not current_user.is_admin:
        flash('관리자만 접근할 수 있습니다.')
        return redirect(url_for('dashboard'))
    
    user_id = request.form.get('user_id')
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET ban_until = NULL WHERE id = ?", (user_id,))
    db.commit()
    
    flash('사용자 정지가 해제되었습니다.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/update_report_status', methods=['POST'])
@login_required
def update_report_status():
    if not current_user.is_admin:
        flash('관리자만 접근할 수 있습니다.')
        return redirect(url_for('dashboard'))
    
    report_id = request.form.get('report_id')
    status = request.form.get('status')
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE report SET status = ? WHERE id = ?", (status, report_id))
    db.commit()
    
    flash('신고 상태가 업데이트되었습니다.')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    reset_user_passwords()  # 비밀번호 초기화
    socketio.run(app, debug=True)
