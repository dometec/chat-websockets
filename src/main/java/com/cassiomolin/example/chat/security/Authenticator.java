package com.cassiomolin.example.chat.security;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

/**
 * In-memory authenticator.
 *
 * @author cassiomolin
 */
@ApplicationScoped
public class Authenticator {

    private SecureRandom random;

    private Cache<String, String> accessTokens;


    @PostConstruct
    public void init() {
        random = new SecureRandom();
        accessTokens = CacheBuilder.newBuilder()
                .expireAfterAccess(15, TimeUnit.SECONDS) // Entries expire in 15 seconds
                .build();
    }

    public boolean checkCredentials(String username, String password) {
        return username.equals(password);
    }

    public String issueAccessToken(String username) {
        String accessToken = generateRandomString();
        accessTokens.put(accessToken, username);
        return accessToken;
    }

    public Optional<String> getUsernameFromToken(String accessToken) {
        String username = accessTokens.getIfPresent(accessToken);
        if (username == null) {
            return Optional.empty();
        } else {
            accessTokens.invalidate(accessToken); // The token can be used only once
            return Optional.of(username);
        }
    }

    private String generateRandomString() {
        return new BigInteger(130, random).toString(32);
    }
}
