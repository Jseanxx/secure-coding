import sqlite3
import uuid
from werkzeug.security import generate_password_hash
from datetime import datetime

def create_admin():
    try:
        # 데이터베이스 연결
        conn = sqlite3.connect('market.db')
        conn.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
        cursor = conn.cursor()
        
        # 트랜잭션 시작
        cursor.execute("BEGIN TRANSACTION")
        
        # 관리자 계정 생성
        admin_id = str(uuid.uuid4())
        admin_username = 'admin'
        admin_password = '1234'  # 비밀번호를 1234로 설정
        hashed_password = generate_password_hash(admin_password)
        
        # 기존 관리자 계정이 있는지 확인
        cursor.execute("SELECT * FROM user WHERE username = ?", (admin_username,))
        existing_admin = cursor.fetchone()
        
        if existing_admin:
            # 기존 관리자 계정 업데이트
            cursor.execute("""
                UPDATE user 
                SET password = ?, is_admin = 1, ban_until = NULL
                WHERE username = ? AND is_admin = 1
            """, (hashed_password, admin_username))
            print("관리자 계정이 업데이트되었습니다.")
        else:
            # 관리자 계정 생성
            cursor.execute("""
                INSERT INTO user (id, username, password, is_admin, ban_until)
                VALUES (?, ?, ?, 1, NULL)
            """, (admin_id, admin_username, hashed_password))
            print("관리자 계정이 생성되었습니다.")
        
        # 트랜잭션 커밋
        conn.commit()
        
        print(f"아이디: {admin_username}")
        print(f"비밀번호: {admin_password}")
        
    except Exception as e:
        # 오류 발생 시 롤백
        conn.rollback()
        print(f"오류가 발생했습니다: {str(e)}")
        raise
    finally:
        # 연결 종료
        conn.close()

if __name__ == '__main__':
    create_admin() 