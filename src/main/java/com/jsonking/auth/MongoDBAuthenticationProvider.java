package com.jsonking.auth;

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

/**
 * An AuthenticationProvider that authenticates users against users stored in MongoDB.
 * Uses username and password
 *
 * The user is authenticated if the client can list databases.
 * See https://docs.mongodb.com/manual/reference/command/listDatabases/
 *
 * Useful when users should only be granted access if they have a valid account in the MongoDB database.
 */
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
        MongoCredential credential = createCredential(username, authentication, connString);

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

    private MongoCredential createCredential(String username, UsernamePasswordAuthenticationToken authentication, ConnectionString connString) {
        char[] chars = authentication.getCredentials().toString().toCharArray();
        return MongoCredential.createCredential(username, connString.getDatabase(), chars);
    }
}
