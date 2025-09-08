package com.github.detiuaveiro.auth.auth.api;

import com.github.detiuaveiro.auth.auth.api.objects.Challenge;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * https://stackabuse.com/how-to-send-http-requests-in-java/
 */
public interface Requests {

    static void getSite() throws IOException {
        final URL url = new URL("https://localhost:80/");
        final HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        // Convert the requestData into bytes
        byte[] requestDataByes = "".getBytes(StandardCharsets.UTF_8);

        // Set the doOutput flag to true
        connection.setDoOutput(true);

        // Get the output stream of the connection instance
        // and add the parameter to the request
        try (DataOutputStream writer = new DataOutputStream(connection.getOutputStream())) {
            writer.write(requestDataByes);
        }
    }

    static Challenge sendChallenge(Challenge challenge) throws IOException, ParseException {
//        final URL url = new URL("https://localhost:443/e-chap?username=bananana&hello=yo");
        final URL url = new URL("https://localhost:443/e-chap?" + challenge.toAPIMethod());
        System.out.println(url);
        final HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

        connection.setRequestMethod("GET");

//        byte[] requestDataByes = "username=bananana&hello=yo".getBytes(StandardCharsets.UTF_8);

        // To store our response
        final StringBuilder content;

// Get the input stream of the connection
        try (BufferedReader input = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            String line;
            content = new StringBuilder();
            while ((line = input.readLine()) != null) {
                // Append each line of the response and separate them
                content.append(line);
                content.append(System.lineSeparator());
            }
        } finally {
            connection.disconnect();
        }

// Output the content to the console
        System.out.println(content);
        final JSONObject o = (JSONObject) new JSONParser().parse(content.toString());

        return new Challenge((String) o.get("challenge"), challenge.getUsername(), (String) o.get("sessionID"));
    }

    static void success() throws IOException {
        final URL url = new URL(Methods.CHALLENGE.getUrl());
        final HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

        connection.setRequestMethod(Methods.CHALLENGE.getType().name());

        // Instantiate a requestData object to store our data
        final StringBuilder requestData = new StringBuilder();
        final Map<String, String> params = new HashMap<>();
        params.put("status", "success");

        for (Map.Entry<String, String> param : params.entrySet()) {
            if (requestData.length() != 0)
                requestData.append('&');
            // Encode the parameter based on the parameter map we've defined
            // and append the values from the map to form a single parameter
            requestData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
            requestData.append('=');
            requestData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
        }

        // Convert the requestData into bytes
        byte[] requestDataByes = requestData.toString().getBytes(StandardCharsets.UTF_8);

        // Set the doOutput flag to true
        connection.setDoOutput(true);

        // Get the output stream of the connection instance
        // and add the parameter to the request
        try (DataOutputStream writer = new DataOutputStream(connection.getOutputStream())) {
            writer.write(requestDataByes);
        }
    }

    static void failure() throws IOException {
        final URL url = new URL(Methods.CHALLENGE.getUrl());
        final HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

        connection.setRequestMethod(Methods.CHALLENGE.getType().name());

        // Instantiate a requestData object to store our data
        final StringBuilder requestData = new StringBuilder();
        final Map<String, String> params = new HashMap<>();
        params.put("status", "failure");

        for (Map.Entry<String, String> param : params.entrySet()) {
            if (requestData.length() != 0)
                requestData.append('&');
            // Encode the parameter based on the parameter map we've defined
            // and append the values from the map to form a single parameter
            requestData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
            requestData.append('=');
            requestData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
        }

        // Convert the requestData into bytes
        byte[] requestDataByes = requestData.toString().getBytes(StandardCharsets.UTF_8);

        // Set the doOutput flag to true
        connection.setDoOutput(true);

        // Get the output stream of the connection instance
        // and add the parameter to the request
        try (DataOutputStream writer = new DataOutputStream(connection.getOutputStream())) {
            writer.write(requestDataByes);
        }
    }
}
