package com.jpk.auth;

import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MongoDBClientFactory {

    public MongoClient create(MongoClientSettings settings) {
        return MongoClients.create(settings);
    }

}
