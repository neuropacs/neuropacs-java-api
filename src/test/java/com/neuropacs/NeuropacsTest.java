package com.neuropacs;

import static org.junit.Assert.*;
import org.junit.Test;



public class NeuropacsTest {
    String serverUrl = "https://zq5jg2kqvj.execute-api.us-east-1.amazonaws.com/staging";
    String apiKey = System.getenv("ADMIN_API_KEY");
    String invalidApiKey = "not_real";
    String productId = "Atypical/MSAp/PSP-v1.0";
    String originType = "Java Integration Tests";
    String invalidOrderId = "not_real";

    @Test
    public void testSuccessfulConnection() {
        Neuropacs npcs = new Neuropacs(serverUrl, apiKey, originType);

        String conn = npcs.connect();

        boolean hasConnectionId = conn.contains("connectionId");
        boolean hasTimestamp = conn.contains("timestamp");
        boolean hasAesKey = conn.contains("aesKey");

        assertTrue(hasAesKey);
        assertTrue(hasTimestamp);
        assertTrue(hasConnectionId);
    }

    @Test
    public void testConnectionFailedInvalidApiKey(){
        Neuropacs npcs = new Neuropacs(serverUrl, invalidApiKey, originType);

        Exception exception = assertThrows(Exception.class, () -> {
            npcs.connect();
        });

        String actualMessage = exception.getMessage();

        assertEquals(actualMessage, "Connection creation failed: API key not found.");

    }

    @Test
    public void testSuccessfulOrderCreation(){
        Neuropacs npcs = new Neuropacs(serverUrl, apiKey, originType);
        npcs.connect();
        String orderId = npcs.newJob();
        assertNotNull(orderId);
    }

    @Test
    public void testMissingSessionParamsForOrderCreation(){
        Neuropacs npcs = new Neuropacs(serverUrl, apiKey, originType);

        Exception exception = assertThrows(Exception.class, () -> {
            npcs.newJob();
        });

        String actualMessage = exception.getMessage();

        assertEquals(actualMessage, "Job creation failed: Missing session parameters, start a new session with 'connect()' and try again.");
    }

    @Test
    public void testInvalidOrderIdForJobRun(){
        Neuropacs npcs = new Neuropacs(serverUrl, apiKey, originType);
        npcs.connect();
        Exception exception = assertThrows(Exception.class, () -> {
            npcs.runJob(invalidOrderId, productId);
        });

        String actualMessage = exception.getMessage();

        assertEquals(actualMessage, "Job run failed: Bucket not found.");
    }

    @Test
    public void testSuccessfulStatusCheck(){
        Neuropacs npcs = new Neuropacs(serverUrl, apiKey, originType);
        npcs.connect();
        String status = npcs.checkStatus("TEST");

        boolean includesStarted = status.contains("started");
        boolean includesFinished = status.contains("finished");
        boolean includesFailed = status.contains("failed");
        boolean includesProgress= status.contains("progress");
        boolean includesInfo = status.contains("info");

        assertNotNull(status);
        assertTrue(includesStarted);
        assertTrue(includesFailed);
        assertTrue(includesFinished);
        assertTrue(includesProgress);
        assertTrue(includesInfo);
    }

    @Test
    public void testSuccessfulResultsRetrieval(){
        Neuropacs npcs = new Neuropacs(serverUrl, apiKey, originType);
        npcs.connect();
        String results = npcs.getResults("TEST", "JSON");

        boolean includesOrderId = results.contains("orderID");
        boolean includesDate = results.contains("date");
        boolean includesInput = results.contains("input");
        boolean includesAnalysis = results.contains("analysis");
        boolean includesMlVersion = results.contains("mlVersion");
        boolean includesResults = results.contains("results");

        assertNotNull(results);
        assertTrue(includesOrderId);
        assertTrue(includesDate);
        assertTrue(includesInput);
        assertTrue(includesAnalysis);
        assertTrue(includesMlVersion);
        assertTrue(includesResults);
    }


}
