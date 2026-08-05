import imaplib
import email
from email.header import decode_header
import getpass


# 1. IMAP 서버 주소 설정 (사용할 메일에 따라 선택)
# 구글 메일: 'imap.gmail.com'
# 네이버 메일: 'imap.naver.com'
IMAP_SERVER = 'imap.gmail.com' 

def decode_mime_header(header_value):
    """
    이메일 헤더의 인코딩된 문자열(예: =?utf-8?B?...)을 
    사람이 읽을 수 있는 일반 문자열로 변환하는 함수입니다.
    """
    if not header_value:
        return "정보 없음"
    
    decoded_text = ""
    # decode_header는 [(디코딩된 바이트/문자열, 문자셋), ...] 형태의 리스트를 반환합니다.
    for text_part, charset in decode_header(header_value):
        if isinstance(text_part, bytes):
            # 바이트 형태인 경우 지정된 문자셋으로 디코딩합니다.
            charset = charset or 'utf-8' # 문자셋이 없으면 기본값으로 utf-8 사용
            try:
                decoded_text += text_part.decode(charset)
            except LookupError:
                # 알 수 없는 문자셋인 경우 오류를 무시하고 utf-8로 시도
                decoded_text += text_part.decode('utf-8', errors='ignore')
        else:
            # 이미 문자열인 경우 그대로 추가
            decoded_text += text_part
            
    return decoded_text


def get_latest_email_info():
    """
    메일 서버에 접속하여 가장 최근 메일 1개의 제목과 발신자를 출력합니다.
    """
    # 사용자로부터 이메일 주소와 앱 비밀번호 입력 받기
    print(f"[{IMAP_SERVER}] 메일 서버 접속 준비")
    user_email = input("이메일 주소를 입력하세요: ")
    # getpass는 터미널에서 비밀번호 입력 시 화면에 노출되지 않도록 해줍니다.
    app_password = getpass.getpass("앱 비밀번호를 입력하세요: ")
    
    mail_server = None
    try:
        # 2. SSL 암호화 통신으로 IMAP 서버 연결 (포트 993)
        print("\n서버에 연결 중입니다...")
        mail_server = imaplib.IMAP4_SSL(IMAP_SERVER)
        
        # 3. 로그인
        mail_server.login(user_email, app_password)
        print("로그인 성공!")
        
        # 4. '받은편지함(INBOX)' 폴더 선택
        mail_server.select("INBOX")
        
        # 5. 받은편지함의 모든 메일 검색 ('ALL')
        # 서버는 메일들의 고유 ID 리스트를 반환합니다.
        status, messages = mail_server.search(None, "ALL")
        
        if status != "OK":
            print("메일을 불러오는 데 실패했습니다.")
            return
            
        # 메일 ID들을 리스트 형태로 변환 (예: b'1 2 3 4' -> ['1', '2', '3', '4'])
        mail_id_list = messages[0].split()
        
        if not mail_id_list:
            print("받은편지함에 메일이 없습니다.")
            return
            
        # 6. 가장 최신 메일의 ID 추출 (리스트의 마지막 요소)
        latest_email_id = mail_id_list[-1]
        print(f"가장 최신 메일(ID: {latest_email_id.decode()})을 가져옵니다...\n")
        
        # 7. 해당 ID의 메일 데이터를 RFC822(전체 메일 원본) 형식으로 가져오기
        status, msg_data = mail_server.fetch(latest_email_id, "(RFC822)")
        
        # 8. 가져온 바이트 데이터를 파이썬 email 객체로 변환 및 파싱
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                # response_part[1]에 실제 이메일 데이터가 들어있음
                msg = email.message_from_bytes(response_part[1])
                
                # 9. 헤더 추출 및 디코딩 (Subject: 제목, From: 보낸 사람)
                subject = decode_mime_header(msg.get("Subject"))
                sender = decode_mime_header(msg.get("From"))
                date = msg.get("Date")
                
                # 결과 출력
                print("-" * 50)
                print(f"보낸 사람 : {sender}")
                print(f"메일 제목 : {subject}")
                print(f"수신 날짜 : {date}")
                print("-" * 50)
                
    except imaplib.IMAP4.error as auth_err:
        print(f"\n[인증 오류] 이메일 주소나 앱 비밀번호를 확인해주세요: {auth_err}")
    except Exception as e:
        print(f"\n[오류 발생] 알 수 없는 오류가 발생했습니다: {e}")
    finally:
        # 10. 작업이 끝난 후 서버 연결 안전하게 종료
        if mail_server:
            try:
                mail_server.close() # 선택된 폴더 닫기
                mail_server.logout() # 로그아웃
                print("\n서버 연결을 안전하게 종료했습니다.")
            except:
                pass

if __name__ == "__main__":
    get_latest_email_info()