package com.scaler.userservice.util;

import com.scaler.userservice.model.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtUtil {

    /**
     * Below is JWT Token that is generated.
     * <p>
     * jwtToken = Header (alg) + payload + signature(secretKey)
     * <p>
     * eg: eyJhbGciOiJIUzI1NiJ9.
     *     e2NyZWF0ZWRBdD1XZWQgRmViIDIxIDIwOjAwOjAzIElTVCAyMDI0LCByb2xlcz1bXSwgZW1haWw9amVldmFuQGdtYWlsLmNvbX0.
     *     QsLWfBoHiKAplXN6bCzCaNm2edXf1yxkAjUtAXs_nkE
     */
    public static String generateJWT(User user) {

        /* Payload */
        Map<String, Object> jsonForJwt = new HashMap<>();
        jsonForJwt.put("email", user.getEmail());
        jsonForJwt.put("roles", user.getRoles());
        jsonForJwt.put("createdAt", new Date());

        /* Header */
        MacAlgorithm alg = Jwts.SIG.HS256;

        /* Signature */
        SecretKey SecretKey = alg.key().build();

        System.out.println("KEY Generated Is: " + Arrays.toString(SecretKey.getEncoded()));

        return Jwts.builder().claims(jsonForJwt).signWith(SecretKey, alg).compact();
    }
}
