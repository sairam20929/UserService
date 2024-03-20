package com.scaler.userservice.util;

import com.scaler.userservice.model.User;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {

    private static SecretKey secretKey;

    @Autowired
    public JwtUtil(SecretKey secretKey) {
        JwtUtil.secretKey = secretKey;
    }

    /**
     * Below is JWT Token that is generated.
     * <p>
     * jwtToken = Header (alg) + payload + signature(secretKey)
     * <p>
     * eg: eyJhbGciOiJIUzI1NiJ9.
     * e2NyZWF0ZWRBdD1XZWQgRmViIDIxIDIwOjAwOjAzIElTVCAyMDI0LCByb2xlcz1bXSwgZW1haWw9amVldmFuQGdtYWlsLmNvbX0.
     * QsLWfBoHiKAplXN6bCzCaNm2edXf1yxkAjUtAXs_nkE
     */

    public static String generateJWT(User user) {

        /* Payload */
        Map<String, Object> jsonForJwt = new HashMap<>();
        jsonForJwt.put("email", user.getEmail());
        jsonForJwt.put("roles", user.getRoles());
        jsonForJwt.put("createdAt", new Date());
        jsonForJwt.put("expiryTime", new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10));

        return Jwts.builder().claims(jsonForJwt).signWith(secretKey).compact();
    }

}
