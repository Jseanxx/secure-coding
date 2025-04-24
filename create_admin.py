import sqlite3
import uuid
from werkzeug.security import generate_password_hash

def create_admin():
    # 데이터베이스 연결
    conn = sqlite3.connect('market.db')
    cursor = conn.cursor()
    
    # 관리자 계정 생성
    admin_id = str(uuid.uuid4())
    admin_username = 'admin'
    admin_password = 'admin1234'
    hashed_password = generate_password_hash(admin_password)
    
    # 기존 관리자 계정이 있는지 확인
    cursor.execute("SELECT * FROM user WHERE username = ?", (admin_username,))
    existing_admin = cursor.fetchone()
    
    if existing_admin:
        print("이미 관리자 계정이 존재합니다.")
    else:
        # 관리자 계정 생성
        cursor.execute("""
            INSERT INTO user (id, username, password, is_admin)
            VALUES (?, ?, ?, 1)
        """, (admin_id, admin_username, hashed_password))
        conn.commit()
        print("관리자 계정이 생성되었습니다.")
        print(f"아이디: {admin_username}")
        print(f"비밀번호: {admin_password}")
    
    conn.close()

if __name__ == '__main__':
    create_admin() 