package com.jsonking.auth;

import com.mongodb.MongoClientSettings;
import com.mongodb.MongoSecurityException;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoIterable;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(SpringJUnit4ClassRunner.class)
public class MongoDBAuthenticationProviderTest {

    private String username = "test_user";

    private MongoDBAuthenticationProvider authenticationProvider;

    @Mock private MongoDBClientFactory clientFactory;
    @Mock private MongoClient client;
    @Mock private MongoIterable<String> iterable;

    @Before
    public void setup() {
        String connectionString = "mongodb://nohost:12345/testDB";
        authenticationProvider = new MongoDBAuthenticationProvider(connectionString, clientFactory);

        when(clientFactory.create(any(MongoClientSettings.class))).thenReturn(client);
        when(client.listDatabaseNames()).thenReturn(iterable);
    }

    @Test
    public void testUserIsReturnedWhenIsAuthenticatedAndCanListOneDatabase() {

        when(iterable.first()).thenReturn("testDB");

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username,"fakeCredentials");
        UserDetails userDetails = authenticationProvider.retrieveUser(username, token);
        assertEquals(username, userDetails.getUsername());
    }

    @Test(expected = BadCredentialsException.class)
    public void testExceptionIsThrownWhenUserCannotBeListDatabases() {

        when(iterable.first()).thenThrow(new MongoSecurityException(null, "from unit test"));

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username,"fakeCredentials");
        authenticationProvider.retrieveUser(username, token);
    }

}
