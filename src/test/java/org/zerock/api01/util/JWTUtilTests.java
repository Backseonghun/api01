package org.zerock.api01.util;

import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.HashMap;
import java.util.Map;

@SpringBootTest
@Log4j2
public class JWTUtilTests {
    @Autowired
    private JWTUtil jwtUtil;

    @Test
    public void testGenerate() {
        Map<String, Object> claimMap = Map.of("mid","ABCDE");
        String jwtStr = jwtUtil.generateToken(claimMap,1);
        log.info(jwtStr);
    }
    @Test
    public void testValidate(){
        String jwtStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MTY1MjgwMjMsIm1pZCI6IkFCQ0RFIiwiaWF0IjoxNzE2NTI3OTYzfQ.iSKkSrv143QfqnkIDrnKMibaZDgXRXDYZzd8PRibqDw";
        Map<String, Object> claim = jwtUtil.validateToken(jwtStr);
        log.info(claim);
    }

    @Test
    public void testAll(){
        String jwtStr = jwtUtil.generateToken(Map.of("mid","AAAA","email","aaaa@bbb.com"),1);
        log.info(jwtStr);
        Map<String,Object> claim = jwtUtil.validateToken(jwtStr);
        log.info("mid"+claim.get("mid"));
        log.info("email"+claim.get("email"));
    }
}
