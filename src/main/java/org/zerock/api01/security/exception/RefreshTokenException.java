package org.zerock.api01.security.exception;

import com.google.gson.Gson;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.util.Date;
import java.util.Map;

public class RefreshTokenException extends RuntimeException {
    private  ErrorCase errorCase;

    public  enum  ErrorCase {
        NO_ACCESS, BAD_ACCESS, NO_REFRESH, OLD_REFRESH, BAD_REFRESH
    }
    public RefreshTokenException(ErrorCase errorCase) {
        super(errorCase.name());
        this.errorCase = errorCase;
    }
        
    public void sendResponseError(HttpServletResponse response){
        // 실행 결과 코드 401번 설정
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        // JSON 형식의 데이터를 반환하도록 설정
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        // Gson 을 이용하여 에러메세지를 JSON 형식으로 변환 후 response에 설정
        Gson gson = new Gson();
        String responseStr = gson.toJson(Map.of("msg",errorCase.name(),"time",new Date()));

        try {
            response.getWriter().println(responseStr);
        }catch (IOException e){
            throw new RuntimeException(e);
        }
    }
}
