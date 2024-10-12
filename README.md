## JWT 전략

- AccessToken (AT)
- RefreshToken (RT)
- 1개의 RefreshToken만 Cache(Redis)에 저장
- RefreshToken은 Rotate 전략 사용
- RefreshToken에 대한 BlackList 적용

> RT 1개에 대해서만 Rotate를 사용하기에, Blacklist는 큰 의미가 없을 수 있다.