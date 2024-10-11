# 테스트 케이스

## 회원가입
 - [x] 회원가입 시도시 성공

## 권한

### 익명 권한
- [x] 익명 -> private(특정 역할 및 인증) uri 접근 실패
- [x] 익명 -> public uri에 접근 성공

### Member 권한
- [x] Member -> public uri 접근 성공
- [x] Member -> private(Member / 인증) uri 접근
- [x] Member -> private(Member) uri 접근 실패

### Admin 권한
- [x] Admin -> public uri 접근 성공
- [x] Admin -> private (Admin / 인증) uri 접근

## JWT

### AccessToken (AT)
- [x] 로그인 -> AT 발급 성공
- [x] AT -> private uri 접근 성공
- [x] 만료된 AT -> private uri 접근 실패

### RefreshToken (RT)
- [x] 로그인 -> RT 발급 성공
- [x] RT -> reissue uri 접근 -> AT + AT 재발급
- [x] 만료된 RT -> reissue uri 접근 -> 토큰 재발급X

### RefreshToken - Cache(Redis)
- [x] 로그인 -> 발급된 RT는 Cache에 저장
- [x] RT -> reissue uri 접근 -> Cache에서 기존 RT 제거, 새로운 RT 저장
- [x] 만료된 RT -> reissue uri 접근 -> Cache에서 만료된 RT 제거

### RefreshToken - BlackList(Redis)
- [ ] 로그인 -> 발급된 RT는 BlcakList에 없음
- [ ] RT -> reissue uri 접근 -> 기존 RT는 BlackList에 있고, 새로운 RT는 BlackList에 없음.
- [ ] 블랙리스트RT -> reissue uri 접근 -> 토큰 재발급 X
