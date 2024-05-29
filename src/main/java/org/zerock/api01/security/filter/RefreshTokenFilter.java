package org.zerock.api01.security.filter;

import com.google.gson.Gson;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;
import org.zerock.api01.security.exception.RefreshTokenException;
import org.zerock.api01.util.JWTUtil;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class RefreshTokenFilter extends OncePerRequestFilter {
    private final String refreshPath;
    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 요청 URL PATH 변수에 저장, 취득
        String path = request.getRequestURI();
        // 요청 URL이 ReFreshPath 가 아니면 필터로 처리
        if(!path.equals(refreshPath)){
            log.info("skip refresh token filter .........");
            filterChain.doFilter(request, response);
            return;
        }
        log.info("refresh token filter ....run...................................1");

        Map<String, String> tokens = parseRequestJSON(request);

        String accessToken = tokens.get("accessToken");
        String refreshToken = tokens.get("refreshToken");

        log.info("accessToken : " + accessToken);
        log.info("refreshToken : " + refreshToken);

        try {
            checkAccessToken(accessToken);
        }catch (RefreshTokenException refreshTokenException){
            refreshTokenException.sendResponseError(response);
            return;
        }
        // try 문 안에서 선언 변수는 try 문 밖에서는 사용할 수 없기 때문에 밖에서 먼저 선언
        Map<String, Object> refreshClaims = null;
        try{
            // refreshToken 의 확인
            refreshClaims = checkRefreshToken(refreshToken);
            log.info(refreshClaims);
            // 토큰의 만료기한을 변수에 저장
            Integer exp = (Integer) refreshClaims.get("exp");
            // Integer 값으로 저장된 만료기한을 시간 타입으로 변환
            Date expTime = new Date(Instant.ofEpochMilli(exp).toEpochMilli() * 1000);
            Date current = new Date(System.currentTimeMillis());

            long gapTime = (expTime.getTime() - current.getTime());

            log.info("--------------------------------------");
            log.info("current : " + current);
            log.info("expTime : " + expTime);
            log.info("gap: " + gapTime);


            String mid = (String) refreshClaims.get("mid");

            String accessTokenValue = jwtUtil.generateToken(Map.of("mid", mid), 1);
            String refreshTokenValue = tokens.get("refreshToken");

            if(gapTime < (1000 * 60 * 60 * 24 * 3)){
                log.info("new Refresh Token required.....");
                refreshTokenValue = jwtUtil.generateToken(Map.of("mid", mid), 30);
            }
            log.info("Refresh Token result..................................");
            log.info("accessTokenValue : " + accessTokenValue);
            log.info("refreshTokenValue : " + refreshTokenValue);
            // 요청페이지에 새로운 토큰들을 보내주는 처리
            sendTokens(accessTokenValue, refreshTokenValue, response);

        }catch (RefreshTokenException refreshTokenException){
            refreshTokenException.sendResponseError(response);
        }
    }
    // 엑세스 토큰이 정상인지 확인하는 메서드
    private Map<String, String> parseRequestJSON(HttpServletRequest request) {
        try (Reader reader = new InputStreamReader(request.getInputStream())) {
            Gson gson = new Gson();
            return gson.fromJson(reader, Map.class);
        }catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;
    }
    private void checkAccessToken(String accessToken) throws RefreshTokenException {
        try{
            jwtUtil.validateToken(accessToken);
        }catch (ExpiredJwtException expiredJwtException) {
            log.info("Access Token has expired");
        }catch (Exception exception){
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.NO_ACCESS);
        }
    }
    private Map<String, Object> checkRefreshToken(String refreshToken) throws RefreshTokenException {
        try {
            Map<String, Object> values = jwtUtil.validateToken(refreshToken);
            return values;
        }catch (ExpiredJwtException expiredJwtException) {
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.OLD_REFRESH);
        }catch (MalformedJwtException malformedJwtException){
            log.info("MalformedJwtException---------------------------");
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.NO_REFRESH);
        }catch (Exception exception){
            new RefreshTokenException(RefreshTokenException.ErrorCase.NO_REFRESH);
        }
        return null;
    }
    private  void sendTokens(String accessTokenValue, String refreshTokenValue, HttpServletResponse response){
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        Gson gson = new Gson();

        String jsonStr = gson.toJson(Map.of("accessToken", accessTokenValue, "refreshToken", refreshTokenValue));

        try {
            // response 에 토큰들을 설정
            response.getWriter().println(jsonStr);
        }catch (IOException e){
            throw new RuntimeException(e);
        }
    }
}
