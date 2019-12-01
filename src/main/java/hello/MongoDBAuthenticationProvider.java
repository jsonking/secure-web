package hello;

import com.mongodb.MongoClientSettings;
import com.mongodb.MongoCredential;
import com.mongodb.MongoSecurityException;
import com.mongodb.ServerAddress;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

@Service
public class MongoDBAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    private static Logger logger = LoggerFactory.getLogger(MongoDBAuthenticationProvider.class);

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        MongoCredential credential = MongoCredential.createCredential(username, "admin", authentication.getCredentials().toString().toCharArray());

        MongoClientSettings settings = MongoClientSettings.builder()
                .credential(credential)
                .applyToClusterSettings(builder ->
                        builder.hosts(List.of(new ServerAddress("localhost", 27017))))
                .build();


        try(MongoClient mongoClient = MongoClients.create(settings)) {
            logger.info("Attempting to authenticate user '{}'", username);
            mongoClient.listDatabases().first();
            logger.info("User successfully authenticated user '{}'", username);
        } catch(MongoSecurityException mse) {
            String message = String.format("User '%s' was not authenticated.", username);
            logger.warn(message, mse);
            throw new BadCredentialsException(message, mse);
        }
        return new User(username, authentication.getCredentials().toString(), Collections.emptyList());
    }
}
