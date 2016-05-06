/*
 * Copyright © 2015 Packt Publishing  - All Rights Reserved.
 * Unauthorized copying of this file, via any medium is strictly prohibited.
 */
package com.dfm.oauth1.client;

import org.apache.commons.lang3.RandomStringUtils;
import org.glassfish.jersey.SslConfigurator;
import org.glassfish.jersey.client.oauth1.AccessToken;
import org.glassfish.jersey.client.oauth1.ConsumerCredentials;
import org.glassfish.jersey.client.oauth1.OAuth1AuthorizationFlow;
import org.glassfish.jersey.client.oauth1.OAuth1ClientSupport;
import org.glassfish.jersey.jackson.JacksonFeature;
import org.glassfish.jersey.oauth1.signature.OAuth1Parameters;

import javax.net.ssl.SSLContext;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.Feature;
import javax.ws.rs.core.Response;
import java.io.*;
import java.nio.charset.Charset;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Properties;

/**
 *
 * @author Jobinesh
 */
public class OAuth1Client {
    private static final String BASE_URI ="migration.dfmdev.com";
    private static final String POSTS_URI = "https://" + BASE_URI + "/wp-json/wp/v2/posts/1";
    private static final BufferedReader IN = new BufferedReader(new InputStreamReader(System.in, Charset.forName("UTF-8")));
    //private static final Properties PROPERTIES = new Properties();
    private static final String PROPERTIES_FILE_NAME = BASE_URI + ".properties";
    private static final String PROPERTY_ACCESS_TOKEN = "accesstoken";
    private static final String PROPERTY_ACCESS_TOKEN_SECRET = "accesstokenSecret";
    private static final String PROPERTY_CONSUMER_KEY = "consumerKey";
    private static final String PROPERTY_CONSUMER_SECRET = "consumerSecret";
    private Properties clientCredentials;

    public String readPosts(String WordPressAPI) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, KeyManagementException {
        // retrieve client token and secret from the property file
        clientCredentials = loadClientProperties(PROPERTIES_FILE_NAME);
        ConsumerCredentials consumerCredentials = new ConsumerCredentials(clientCredentials.getProperty(PROPERTY_CONSUMER_KEY),
                clientCredentials.getProperty(PROPERTY_CONSUMER_SECRET));

        Feature filterFeature;

        // Set the Nonce and Timestamp parameters
        String nonce = getNonce();
        String timestamp = getTimestamp();

        if (clientCredentials.getProperty(PROPERTY_ACCESS_TOKEN) == null) {
            // To get Access Token perform the Authorization Flow first,
            // let the user approve our app and get Access Token.

            SSLContext context = SslConfigurator.newInstance()
                    .trustStoreFile("C:\\Users\\Mick\\Documents\\Cloud\\Google Drive\\mjacobsen@denverpost.com\\Dev\\mason\\share\\Projects\\InstallCert\\jssecacerts")
                    .keyPassword("changeit").createSSLContext();


            Client client = ClientBuilder.newBuilder()
                    .sslContext(context)
                    .build();

            System.out.println(String.format("%s=%s", "oauth_consumer_key", consumerCredentials.getConsumerKey()));
            System.out.println(String.format("%s=%s", OAuth1Parameters.SIGNATURE_METHOD, "HMAC-SHA1"));
            System.out.println(String.format("%s=%s", OAuth1Parameters.TIMESTAMP, timestamp));
            System.out.println(String.format("%s=%s", OAuth1Parameters.NONCE, nonce));
            System.out.println(String.format("%s=%s", OAuth1Parameters.CALLBACK, "oob"));
            final OAuth1AuthorizationFlow authorizationFlow = OAuth1ClientSupport.builder(consumerCredentials)
                    .authorizationFlow(
                            "http://" + BASE_URI + "/oauth1/request?wp_scope=*",
                            "http://" + BASE_URI + "/oauth1/access",
                            "http://" + BASE_URI + "/oauth1/authorize")
                    .callbackUri("")
                    .client(client)
                    .build();

            //This demo asks user to do the following steps manually.
            //Real life web app will automate this tasks
            String authorizationUri = authorizationUri = authorizationFlow.start();


            System.out.println("Enter the following URI into a web browser and authorize me: ");
            System.out.println(authorizationUri);
            System.out.print("Enter the authorization code: ");

            final String verifier;
            try {
                verifier = IN.readLine();
            } catch (final IOException ex) {
                throw new RuntimeException(ex);
            }
            final AccessToken accessToken = authorizationFlow.finish(verifier);


            // store access token for next application execution
            clientCredentials.setProperty(PROPERTY_ACCESS_TOKEN, accessToken.getToken());
            clientCredentials.setProperty(PROPERTY_ACCESS_TOKEN_SECRET, accessToken.getAccessTokenSecret());

            // persist the current consumer key/secret and token/secret for future use
            storeSettings();

            // get the filter feature that will configure the client with consumer credentials and
            // received access token. This will be used with client to call API
            filterFeature = authorizationFlow.getOAuth1Feature();
        } else {
            //Access tokens are already available from last execution
            final AccessToken storedToken = new AccessToken(clientCredentials.getProperty(PROPERTY_ACCESS_TOKEN),
                    clientCredentials.getProperty(PROPERTY_ACCESS_TOKEN_SECRET));
            // build a new filter feature from the stored consumer credentials and access token
            filterFeature = OAuth1ClientSupport.builder(consumerCredentials).feature()
                    .accessToken(storedToken).build();
        }


        SSLContext context = SslConfigurator.newInstance()
                .trustStoreFile("C:\\Users\\Mick\\Documents\\Cloud\\Google Drive\\mjacobsen@denverpost.com\\Dev\\mason\\share\\Projects\\InstallCert\\jssecacerts")
                .keyPassword("changeit").createSSLContext();

        // create a new Jersey client and register filter feature that will add OAuth signatures and
        // JacksonFeature that will process returned JSON data.
        final Client client = ClientBuilder.newBuilder()
                .register(filterFeature)
                .register(JacksonFeature.class)
                .sslContext(context)
                .build();

        // make requests to protected resources
        // (no need to care about the OAuth signatures)
        final Response response = client.target(WordPressAPI).request().get();
        if (response.getStatus() != 200) {
            String errorEntity = null;
            if (response.hasEntity()) {
                errorEntity = response.readEntity(String.class);
            }
            throw new RuntimeException("Request to WordPress was not successful. Response code: "
                    + response.getStatus() + ", reason: " + response.getStatusInfo().getReasonPhrase()
                    + ", entity: " + errorEntity);
        }

        final String posts = response.readEntity(String.class);

        System.out.println("Posts:\n");
        //System.out.println(posts);
        return posts;
    }

    /**
     * Main method that uses OAuth1.0a to access WordPress API.
     *
     * @param args Command line arguments.
     * @throws Exception Thrown when error occurs.
     */
    public static void main(final String[] args) throws Exception {

        String posts = new OAuth1Client().readPosts(POSTS_URI);
        System.out.println(posts);

    }


    /**
     * Read the properties file
     *
     * @param fileName Command line arguments.
     */
    private Properties loadClientProperties(String fileName) {
        Properties properties = new Properties();
        FileInputStream st = null;
        try {
            st = new FileInputStream(fileName);
            properties.load(st);
        } catch (final IOException e) {
            // ignore
        } finally {
            if (st != null) {
                try {
                    st.close();
                } catch (final IOException ex) {
                    // ignore
                }
            }
        }

        for (final String name : new String[]{PROPERTY_CONSUMER_KEY, PROPERTY_CONSUMER_SECRET,
            PROPERTY_ACCESS_TOKEN, PROPERTY_ACCESS_TOKEN_SECRET}) {
            final String value = System.getProperty(name);
            if (value != null) {
                properties.setProperty(name, value);
            }
        }

        if (properties.getProperty(PROPERTY_CONSUMER_KEY) == null
                || properties.getProperty(PROPERTY_CONSUMER_SECRET) == null) {
            System.out.println("No consumerKey and/or consumerSecret found in wirehub.properties file. "
                    + "You have to provide these as properties.");
            System.exit(1);
        }
        return properties;
    }

    private void storeSettings() {
        FileOutputStream st = null;
        try {
            st = new FileOutputStream(PROPERTIES_FILE_NAME);
            clientCredentials.store(st, null);
        } catch (final IOException e) {
            // ignore
        } finally {
            try {
                if (st != null) {
                    st.close();
                }
            } catch (final IOException ex) {
                // ignore
            }
        }
    }

    /**
     * Generates an integer representing the number of seconds since the unix epoch using the
     * date/time the request is issued
     *
     * @return  A timestamp for the request
     */
    private static String getTimestamp()
    {
        return Long.toString((System.currentTimeMillis() / 1000));
    }

    /**
     * Generates a random nonce
     *
     * @return  A unique identifier for the request
     */
    private static String getNonce()
    {
        return RandomStringUtils.randomAlphanumeric(32);
    }
}
