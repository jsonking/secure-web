package com.jpk.auth;

import com.mongodb.*;
import com.mongodb.client.MongoClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class MongoDBAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    private static Logger logger = LoggerFactory.getLogger(MongoDBAuthenticationProvider.class);

    private String connectionString;
    private MongoDBClientFactory clientFactory;

    public MongoDBAuthenticationProvider(
            @Value("${mongo.connection.string:mongodb://localhost:27017/admin}") String connectionString,
            @Autowired MongoDBClientFactory clientFactory) {
        this.connectionString = connectionString;
        this.clientFactory = clientFactory;
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        ConnectionString connString = new ConnectionString(connectionString);
        MongoCredential credential = MongoCredential.createCredential(username, connString.getDatabase(), authentication.getCredentials().toString().toCharArray());

        MongoClientSettings settings = MongoClientSettings.builder()
                .applyConnectionString(connString)
                .credential(credential)
                .build();

        try(MongoClient mongoClient = clientFactory.create(settings)) {
            logger.info("Attempting to authenticate user '{}'", username);
            mongoClient.listDatabaseNames().first();
            logger.info("User successfully authenticated user '{}'", username);
        } catch(MongoSecurityException mse) {
            String message = String.format("User '%s' was not authenticated.", username);
            logger.warn(message, mse);
            throw new BadCredentialsException(message, mse);
        }
        return new User(username, authentication.getCredentials().toString(), Collections.emptyList());
    }
}
