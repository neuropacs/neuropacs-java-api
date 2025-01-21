package com.neuropacs;

import static org.junit.Assert.*;
import org.junit.Test;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;



public class NeuropacsTest {
    String serverUrl = "https://zq5jg2kqvj.execute-api.us-east-1.amazonaws.com/staging";
//    String apiKey = System.getenv("ADMIN_API_KEY");
    String adminKey = "Ln0Zf11LRP9vVB8UgxJNl4RSmoBERexb83CiOvCq";
    String regKey = "r7TK56hInGaj3aNug4Mmc5mqCZ3fVQjT1HilX6Tp";
    String noUsagesRemaining = "DsX5YzUkTq84ddbeprc29Bm20u0ZEdO9jNQxL3Mg";
    String invalidApiKey = "not_real";
    String productId = "Atypical/MSAp/PSP-v1.0";
    String originType = "Java Integration Tests";
    String invalidOrderId = "not_real";

    @Test
    public void testSuccessfulConnection() {
        Neuropacs npcs = new Neuropacs(serverUrl, adminKey, originType);

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
        Neuropacs npcs = new Neuropacs(serverUrl, adminKey, originType);
        npcs.connect();
        String orderId = npcs.newJob();
        assertNotNull(orderId);
    }

    @Test
    public void testMissingSessionParamsForOrderCreation(){
        Neuropacs npcs = new Neuropacs(serverUrl, adminKey, originType);

        Exception exception = assertThrows(Exception.class, () -> {
            npcs.newJob();
        });

        String actualMessage = exception.getMessage();

        assertEquals(actualMessage, "Job creation failed: Missing session parameters, start a new session with 'connect()' and try again.");
    }

    @Test
    public void testSuccessfulDatasetUpload(){
        Neuropacs npcs = new Neuropacs(serverUrl, adminKey, originType);
        npcs.connect();
        String orderId = npcs.newJob();
        boolean upload = npcs.uploadDatasetFromPath(orderId, "src/test/java/com/neuropacs/sample_dataset");
        assertTrue(upload);
    }

    @Test
    public void testInvalidDatasetPath(){
        Neuropacs npcs = new Neuropacs(serverUrl, adminKey, originType);
        npcs.connect();
        String orderId = npcs.newJob();
        Exception exception = assertThrows(Exception.class, () -> {
            npcs.uploadDatasetFromPath(orderId, "src/test/java/com/neuropacs/not_real");
        });

        String actualMessage = exception.getMessage();
        assertEquals(actualMessage, "Failed to upload dataset from path: datasetPath does not exist.");
    }


    @Test
    public void testInvalidOrderIdForJobRun(){
        Neuropacs npcs = new Neuropacs(serverUrl, adminKey, originType);
        npcs.connect();
        Exception exception = assertThrows(Exception.class, () -> {
            npcs.runJob(invalidOrderId, productId);
        });

        String actualMessage = exception.getMessage();

        assertEquals(actualMessage, "Job run failed: Bucket not found.");
    }

    @Test
    public void testNoUsagesRemainingOnJobRun(){
        Neuropacs npcs = new Neuropacs(serverUrl, noUsagesRemaining, originType);
        npcs.connect();
        Exception exception = assertThrows(Exception.class, () -> {
            npcs.runJob(invalidOrderId, productId);
        });

        String actualMessage = exception.getMessage();

        assertEquals(actualMessage, "Job run failed: No API key usages remaining.");
    }


    @Test
    public void testSuccessfulStatusCheck(){
        Neuropacs npcs = new Neuropacs(serverUrl, adminKey, originType);
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
        Neuropacs npcs = new Neuropacs(serverUrl, adminKey, originType);
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


    @Test
    public void testSuccessfulReportRetrievalInTxtFormat() {
        // Initialize Neuropacs
        Neuropacs npcsTemp = new Neuropacs("https://ud7cvn39n4.execute-api.us-east-1.amazonaws.com/sandbox", "generate_api_key");

        // Calculate dates
        SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy");
        Date today = new Date();
        Calendar cal = Calendar.getInstance();
        cal.setTime(today);
        cal.add(Calendar.DATE, -10);
        Date tenDaysAgo = cal.getTime();

        String todayStr = sdf.format(today);
        String tenDaysAgoStr = sdf.format(tenDaysAgo);

        npcsTemp.connect();

        String report = npcsTemp.getReport("txt", tenDaysAgoStr, todayStr);

        assertTrue(report != null && !report.isEmpty() && report.contains("apiKey"));
    }

    @Test
    public void testSuccessfulReportRetrievalInEmailFormat() {
        // Initialize Neuropacs
        Neuropacs npcsTemp = new Neuropacs("https://ud7cvn39n4.execute-api.us-east-1.amazonaws.com/sandbox", "generate_api_key");

        // Calculate dates
        SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy");
        Date today = new Date();
        Calendar cal = Calendar.getInstance();
        cal.setTime(today);
        cal.add(Calendar.DATE, -10);
        Date tenDaysAgo = cal.getTime();

        String todayStr = sdf.format(today);
        String tenDaysAgoStr = sdf.format(tenDaysAgo);

        npcsTemp.connect();

        String report = npcsTemp.getReport("email", tenDaysAgoStr, todayStr);

        assertTrue(report != null && !report.isEmpty() && report.contains("success"));
    }

    @Test
    public void testInvalidEndDateFormatInReportRetrieval() {
        // Initialize Neuropacs
        Neuropacs npcsTemp = new Neuropacs("https://ud7cvn39n4.execute-api.us-east-1.amazonaws.com/sandbox", "generate_api_key");

        // Calculate dates
        SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy");
        Date today = new Date();
        Calendar cal = Calendar.getInstance();
        cal.setTime(today);
        cal.add(Calendar.DATE, -10);
        Date tenDaysAgo = cal.getTime();

        String tenDaysAgoStr = sdf.format(tenDaysAgo);

        npcsTemp.connect();

        Exception exception = assertThrows(Exception.class, () -> {
            npcsTemp.getReport("email", tenDaysAgoStr, "invalid");
        });

        String actualMessage = exception.getMessage();

        assertEquals(actualMessage, "Report retrieval failed: Invalid date format (MM/DD/YYYY).");
    }

    @Test
    public void testInvalidStartDateFormatInReportRetrieval() {
        // Initialize Neuropacs
        Neuropacs npcsTemp = new Neuropacs("https://ud7cvn39n4.execute-api.us-east-1.amazonaws.com/sandbox", "generate_api_key");

        // Calculate dates
        SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy");
        Date today = new Date();
        Calendar cal = Calendar.getInstance();
        cal.setTime(today);
        cal.add(Calendar.DATE, -10);
        Date tenDaysAgo = cal.getTime();

        String tenDaysAgoStr = sdf.format(tenDaysAgo);

        npcsTemp.connect();

        Exception exception = assertThrows(Exception.class, () -> {
            npcsTemp.getReport("email", "invalid", tenDaysAgoStr);
        });

        String actualMessage = exception.getMessage();

        assertEquals(actualMessage, "Report retrieval failed: Invalid date format (MM/DD/YYYY).");
    }

    @Test
    public void testEndDateExceedsCurrentDateInReportRetrieval() {
        // Initialize Neuropacs
        Neuropacs npcsTemp = new Neuropacs("https://ud7cvn39n4.execute-api.us-east-1.amazonaws.com/sandbox", "generate_api_key");

        // Calculate dates
        SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy");
        Date today = new Date();
        Calendar cal = Calendar.getInstance();
        cal.setTime(today);
        cal.add(Calendar.DATE, +10);
        Date tenDaysAhead = cal.getTime();

        String todayStr = sdf.format(today);
        String tenDaysAheadStr = sdf.format(tenDaysAhead);

        npcsTemp.connect();

        Exception exception = assertThrows(Exception.class, () -> {
            npcsTemp.getReport("email", todayStr, tenDaysAheadStr);
        });

        String actualMessage = exception.getMessage();

        assertEquals(actualMessage, "Report retrieval failed: Provided date must not exceed current date.");
    }

    @Test
    public void testStartDateExceedsCurrentDateInReportRetrieval() {
        // Initialize Neuropacs
        Neuropacs npcsTemp = new Neuropacs("https://ud7cvn39n4.execute-api.us-east-1.amazonaws.com/sandbox", "generate_api_key");

        // Calculate dates
        SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy");
        Date today = new Date();
        Calendar cal = Calendar.getInstance();
        cal.setTime(today);
        cal.add(Calendar.DATE, +10);
        Date tenDaysAhead = cal.getTime();

        String todayStr = sdf.format(today);
        String tenDaysAheadStr = sdf.format(tenDaysAhead);

        npcsTemp.connect();

        Exception exception = assertThrows(Exception.class, () -> {
            npcsTemp.getReport("email", tenDaysAheadStr, todayStr);
        });

        String actualMessage = exception.getMessage();

        assertEquals(actualMessage, "Report retrieval failed: Provided date must not exceed current date.");
    }

    @Test
    public void testEndDateBeforeStartDateInReportRetrieval() {
        // Initialize Neuropacs
        Neuropacs npcsTemp = new Neuropacs("https://ud7cvn39n4.execute-api.us-east-1.amazonaws.com/sandbox", "generate_api_key");

        // Calculate dates
        SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy");
        Date today = new Date();
        Calendar cal = Calendar.getInstance();
        cal.setTime(today);
        cal.add(Calendar.DATE, -10);
        Date tenDaysAhead = cal.getTime();

        String todayStr = sdf.format(today);
        String tenDaysAheadStr = sdf.format(tenDaysAhead);

        npcsTemp.connect();

        Exception exception = assertThrows(Exception.class, () -> {
            npcsTemp.getReport("email", todayStr, tenDaysAheadStr);
        });

        String actualMessage = exception.getMessage();

        assertEquals(actualMessage, "Report retrieval failed: startDate must not exceed endDate.");
    }

}
