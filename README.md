# 멘토링 상담 예약 웹앱 (v3: 월간 달력 FullCalendar)

## 핵심 반영 사항
- 학생/교수 화면 모두 '진짜 월간 달력(FullCalendar)' 제공
- 교수: 슬롯 생성(기간/요일/시간대) + 달력에서 슬롯 클릭으로 OPEN/CLOSED 토글
- 학생: 달력에서 슬롯 클릭으로 예약 (1:1은 예약자 이름 비공개, 그룹만 이름 공개)
- 예약/취소/변경은 당일(00:00 이후) 불가
- 초대코드(교수 화면에서 변경 가능)로 학생 회원가입 제한
- Windows 타임존 오류 방지: KST(+09:00) 고정
- bcrypt 길이 제한 회피: pbkdf2_sha256 사용

## 실행(Windows)
```bat
python -m venv venv
venv\Scripts\activate

python -m pip install --upgrade pip
pip install -r requirements.txt

python -m uvicorn app:app --reload --host 127.0.0.1 --port 8000
```
브라우저: http://127.0.0.1:8000

## 초기 교수 계정(화면에 노출되지 않음)
- ID: prof
- PW: prof1234
로그인 후 교수 화면에서 비밀번호 변경 권장

## FullCalendar
- CDN 사용(추가 설치 없음)


## v4 추가 기능
- 교수: 슬롯 표(목록) 제공 + 수정/삭제 + 달력 클릭 시 토글/시간수정/삭제 선택
- 학생: 차수별 내 예약을 상단 표로 표시 + 표에서 취소, 변경(변경 버튼 후 달력에서 목표 슬롯 클릭)
- 달력 이벤트 글씨 잘림 방지 CSS 보강


## 수정(v5.1)
- 달력 이벤트 로딩 URL을 역할별 API로 수정함.
  - 교수 달력: /api/prof/round/{round_id}/events
  - 학생 달력: /api/student/round/{round_id}/events
- 기존 v5에서 달력에 슬롯이 안 보이던 문제(404) 해결.


## v5.1.2 수정
- 학생 '내 예약(표)'가 비는 문제: fetch에 credentials 명시 + 응답 오류/리다이렉트(로그인) 등 상세 메시지 표시.
- 예약 제한(중복 예약) 시 오류 메시지 구체화.
