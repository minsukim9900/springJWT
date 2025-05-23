package com.ureca.SpringJWT.controller;

import com.ureca.SpringJWT.entity.RefreshEntity;
import com.ureca.SpringJWT.jwt.JWTUtil;
import com.ureca.SpringJWT.repository.RefreshRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@RestController
@RequiredArgsConstructor
public class ReissueController {
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {
        // get refresh token
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for(Cookie cookie : cookies) {
            if(cookie.getName().equals("refresh")) {
                refresh = cookie.getValue();
            }
        }

        if(refresh == null) {
            //response status code
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

        // expired check
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {
            //response status code
            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        }

        // 토큰이 refresh인지 확인(발급 시 페이로드에 명시)
        String category = jwtUtil.getCategory(refresh);

        if(!category.equals("refresh")) {
            //response status code
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        //DB에 저장되어 있는지 확인
        Boolean isExist = refreshRepository.existsByRefreshToken(refresh);
        if(!isExist) {
            //response body
            return new ResponseEntity<>("refresh token not found", HttpStatus.BAD_REQUEST);
        }

        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        // make new JWT
        String newAccess = jwtUtil.createJWT("access", username, role, 600000L);
        String newRefresh = jwtUtil.createJWT("refresh", username, role, 86400000L);

        refreshRepository.deleteByRefreshToken(refresh);
        addRefreshEntity(username, refresh, 86400000L);

        // response
        response.setHeader("access", newAccess);
        response.addCookie(new Cookie("refresh", newRefresh));

        return new ResponseEntity<>(HttpStatus.OK);
    }

    private void addRefreshEntity(String username, String refresh, Long expireMs) {
        Date now = new Date(System.currentTimeMillis() + expireMs);

        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setRefreshToken(refresh);
        refreshEntity.setUsername(username);
        refreshEntity.setExpiration(now.toString());

        refreshRepository.save(refreshEntity);
    }
}
