/**
 * File: Neuropacs.java
 * Description: neuropacs Java API
 * Author: Kerrick Cavanaugh
 * Date Created: 09/15/2024
 * Last Updated: 09/30/2024
 */

package com.neuropacs;

// Dependencies
import java.io.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.*;
import javax.crypto.Cipher;
import java.util.UUID;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import java.util.function.Consumer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonFactory;

import jakarta.json.Json;
import jakarta.json.stream.JsonParser;
import jakarta.mail.BodyPart;
import jakarta.mail.internet.MimeMultipart;
import jakarta.mail.util.ByteArrayDataSource;
import org.dcm4che3.data.Attributes;
import org.dcm4che3.data.RemapUIDsAttributesCoercion;
import org.dcm4che3.data.Tag;
import org.dcm4che3.json.JSONReader;
import org.dcm4che3.util.StreamUtils;


// Neuropacs class
public class Neuropacs {
    //    Private instance variables
    private String serverUrl;
    private String apiKey;
    private String originType;
    private String aesKey = null;
    private String connectionId = null;
    private int maxZipSize = 15 * 1024 * 1024; // 15mb
    HttpClient client = HttpClient.newHttpClient();
    ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Neuropacs constructor with all parameters
     * @param serverUrl  URL of server
     * @param apiKey     API key
     * @param originType Origin application (default = 'api')
     */
    public Neuropacs(String serverUrl, String apiKey, String originType) {
        this.serverUrl = serverUrl;
        this.apiKey = apiKey;
        this.originType = originType;
    }

    /**
     * Neuropacs constructor with default originType
     * @param serverUrl URL of server
     * @param apiKey    API key
     */
    public Neuropacs(String serverUrl, String apiKey) {
        this.serverUrl = serverUrl;
        this.apiKey = apiKey;
        this.originType = "API";
    }

    //    Private methods
    /**
     * Generate a random V4 UUID
     * @return  Random V4 UUID string
     */
    private String generateUniqueUUID() {
        return UUID.randomUUID().toString();
    }

    /**
     *  Generate current timestamp in UTC timezone
     * @return  Time/date string in "yyyy-MM-dd HH:mm:ss UTC" format
     */
    private String generateUTCTimeString() {
        LocalDateTime currentDateTime = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        String formattedDateTime = currentDateTime.format(formatter);
        return formattedDateTime + " UTC";
    }

    /**
     * Generate a random AES CTR encryption key
     * @return  Base64 16-byte string AES CTR encryption key
     */
    private String generateAesKey() {
        try {
            // Byte array to hold the AES key
            byte[] aesKey = new byte[16]; // 16 bytes = 128 bits

            // Generate random values for the key
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(aesKey);

            // Base64 encoding
            String base64AesKey = Base64.getEncoder().encodeToString(aesKey);

            this.aesKey = base64AesKey;

            // Encode the byte array to a Base64 string
            return base64AesKey;
        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("AES key generation failed: " + e.getMessage(), e);
        }
    }

    /**
     * Get public key in PEM format for OAEP encryption
     * @return  Base64 string public key
     */
    private String getPublicKey() {
        try {
            // Build URI
            URI uri = URI.create(this.serverUrl + "/api/getPubKey/");

            // Send request
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .header("Origin-Type", this.originType)
                    .GET()
                    .build();

            // Get response
            HttpResponse<String> response = this.client.send(request, HttpResponse.BodyHandlers.ofString());

            // Create JSON from response data
            Map<String, String> jsonMap = this.objectMapper.readValue(response.body(), Map.class);

            // Check failure status
            if (response.statusCode() != 200) {
                throw new RuntimeException(jsonMap.get("error"));
            }

            // Get pub_key attribute from JSON, return public key
            return jsonMap.get("pub_key");
        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("Retrieval of public key failed: " + e.getMessage(), e);
        }
    }

    /**
     * OAEP encrypt plaintext (String)
     * @param plaintext Plaintext to be encrypted
     * @return  Encrypted base64 encoded ciphertext
     */
    private String oaepEncrypt(String plaintext) {
        try {
            // Get public key from class
            String publicKeyPEM = this.getPublicKey();

            // Extract the part of the PEM string between header and footer
            String cleanedKey = publicKeyPEM
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\r", "")
                    .replaceAll("\n", "");

            // Base64 decode the string to get the binary data
            byte[] decodedKey = Base64.getDecoder().decode(cleanedKey);

            // Generate public key object
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            // Specify OAEP encryption params
            OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT
            );

            // Create cipher for plaintext OAEP encryption
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);

            // Perform OAEP encryption
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            // Encode the encrypted bytes as Base64 for easier handling
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("OAEP encryption failed: " + e.getMessage(), e);
        }
    }


    /**
     * Encrypt plaintext with AES-CTR-256 encryption
     * @param plaintext Plaintext (String) to be encrypted
     * @param aesKey    Base64 String AES key
     * @return  Encrypted base64 ciphertext (byte[])
     */
    private byte[] encryptAesCtr(String plaintext, String aesKey){
        try {
            // Create cipher
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            // Generate counter
            byte[] counter = new byte[16];
            SecureRandom secureRandomGenerator = SecureRandom.getInstance("SHA1PRNG", "SUN");
            secureRandomGenerator.nextBytes(counter);

            // Generate IV
            IvParameterSpec iv=new IvParameterSpec(counter);
            byte[] aesKeyBase64 = Base64.getDecoder().decode(aesKey);

            // Create AES key object
            SecretKeySpec key = new SecretKeySpec(aesKeyBase64, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            // Perform encryption
            byte[] encrypted=cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] combined = new byte[counter.length + encrypted.length];

            System.arraycopy(counter,0,combined,0         ,counter.length);
            System.arraycopy(encrypted,0,combined,counter.length,encrypted.length);

            // Return base64 encoded byte[]
            return Base64.getEncoder().encode(combined);
        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("AES encryption failed: " + e.getMessage(), e);
        }
    }


    /**
     * Decrypt ciphertext with AES-CTR-256 decryption
     * @param ciphertext Ciphertext (String) to be decrypted
     * @param aesKey    Base64 String AES key
     * @return Decrypted base64 plaintext (byte[])
     */
    private byte[] decryptAesCtr(String ciphertext, String aesKey) {
        try {
            // Format params
            byte[] ciphertextBase64 = Base64.getDecoder().decode(ciphertext);
            byte[] aesKeyBase64 = Base64.getDecoder().decode(aesKey);

            // Create AES key object
            SecretKeySpec key = new SecretKeySpec(aesKeyBase64, "AES");

            // Extract counter
            byte[] counter = new byte[16];
            System.arraycopy(ciphertextBase64, 0, counter, 0, 16);

            // Extract message
            byte[] message = new byte[ciphertextBase64.length - 16];
            System.arraycopy(ciphertextBase64, 16, message, 0, message.length);

            // Create cipher
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

            // Generate IV
            IvParameterSpec iv = new IvParameterSpec(counter);

            // Perform decryption
            cipher.init(Cipher.DECRYPT_MODE, key, iv);

            // Return decrypted plaintext (byte[])
            return cipher.doFinal(message);
        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("AES decryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Ensure that each filename in ZIP file is unique
     * @param uniqueFilenames   Set of filenames already used
     * @param filename  New filename to be checked
     * @return  New unique filename String (increments with '_x' until not found in set)
     */
    private String ensureUniqueFilename(Set<String> uniqueFilenames, String filename) {
        // If filename not in set, return
        if (!uniqueFilenames.contains(filename)) {
            return filename;
        } else {
            // Append counter value to filename until not in set
            short counter = 1;
            String temp_fn = filename;
            while (uniqueFilenames.contains(temp_fn)) {
                temp_fn = filename + "_" + String.valueOf(counter);
                counter++;
            }
            // Unique filename found, return
            filename = temp_fn;
            return filename;
        }
    }

    /**
     * Start a new S3 multipart upload
     * @param datasetId Base64 datasetId (String)
     * @param zipIndex  Index of zip file
     * @param orderId   Base64 orderId (String)
     * @return Upload Id correlating upload to S3 object
     */
    private String newMultipartUpload(String datasetId, int zipIndex, String orderId){
        try{
            // Build URI
            URI uri = URI.create(this.serverUrl + "/api/multipartUploadRequest/");

            // Build request body
            String requestBody = String.format("{ \"datasetId\": \"%s\", \"zipIndex\": \"%d\", \"orderId\": \"%s\" }", datasetId, zipIndex, orderId);

            // Encrypt request body
            byte[] encryptedRequestBody = this.encryptAesCtr(requestBody, this.aesKey);

            // Build the HTTP request
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .header("Content-Type", "text/plain")
                    .header("Origin-Type", this.originType)
                    .header("Connection-Id", this.connectionId)
                    .POST(HttpRequest.BodyPublishers.ofString(new String(encryptedRequestBody)))
                    .build();

            // Get response body
            HttpResponse<String> response = this.client.send(request, HttpResponse.BodyHandlers.ofString());
            String responseBody = response.body();

            Map<String, String> jsonMap;

            // Error if not successful
            if(response.statusCode() != 200){
                jsonMap = this.objectMapper.readValue(responseBody, Map.class);
                throw new RuntimeException(jsonMap.get("error"));
            }

            // Decrypt response
            byte[] decryptedCipher = this.decryptAesCtr(responseBody, this.aesKey);
            String decryptedString = new String(decryptedCipher, StandardCharsets.UTF_8);

            // Convert to JSON
            jsonMap = this.objectMapper.readValue(decryptedString, Map.class);

            // Extract uploadId field from JSON
            return jsonMap.get("uploadId");

        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("Multipart upload creation failed: " + e.getMessage(), e);
        }
    }

    /**
     *  Complete S3 multipart upload
     * @param orderId   Base64 orderId (String)
     * @param datasetId Base64 datasetId (String)
     * @param zipIndex  Zip file index
     * @param uploadId  Base64 uploadId
     * @param finalParts    JSON object (stringified) used by S3 to ensure all pieces delivered to bucket
     */
    private void completeMultipartUpload(String orderId, String datasetId, int zipIndex, String uploadId, List<Map<String, String>> finalParts){
        try{
            // Build URI
            URI uri = URI.create(this.serverUrl + "/api/completeMultipartUpload/");

            // Stringify JSON final parts
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonFinalParts = objectMapper.writeValueAsString(finalParts);

            // Build request body
            String requestBody = String.format("{ \"datasetId\": \"%s\", \"zipIndex\": \"%d\", \"uploadId\": \"%s\", \"uploadParts\": %s,\"orderId\": \"%s\" }", datasetId, zipIndex, uploadId, jsonFinalParts, orderId);

            // Encrypt request body
            byte[] encryptedRequestBody = this.encryptAesCtr(requestBody, this.aesKey);

            // Build the HTTP request
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .header("Content-Type", "text/plain")
                    .header("Origin-Type", this.originType)
                    .header("Connection-Id", this.connectionId)
                    .POST(HttpRequest.BodyPublishers.ofString(new String(encryptedRequestBody)))
                    .build();

            // Get response
            HttpResponse<String> response = this.client.send(request, HttpResponse.BodyHandlers.ofString());
            String responseBody = response.body();

            Map<String, String> jsonMap;

            // Error if not successful
            if(response.statusCode() != 200){
                jsonMap = this.objectMapper.readValue(responseBody, Map.class);
                throw new RuntimeException(jsonMap.get("error"));
            }

        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("Multipart upload completion failed: " + e.getMessage(), e);
        }
    }

    /**
     *  Upload chunk to bucket with S3 multipart upload
     * @param uploadId Base64 uploadId
     * @param datasetId Base64 datasetId
     * @param zipIndex  Zip file index
     * @param orderId   Base64 orderId
     * @param partNumber    Zip part number
     * @param baos  Zip contents (byte[])
     * @return ETag (String) associated with upload event
     */
    private String uploadMultipartChunk(String uploadId, String datasetId, int zipIndex, String orderId, int partNumber, byte[] baos){
        try{

            // Get presigned URL for chunk upload \\
            // Build request
            URI uri = URI.create(this.serverUrl + "/api/multipartPresignedUrl/");

            String requestBody = String.format("{ \"datasetId\": \"%s\", \"uploadId\": \"%s\", \"partNumber\": \"%d\", \"zipIndex\": \"%d\", \"orderId\": \"%s\" }", datasetId, uploadId, partNumber, zipIndex, orderId);

            byte[] encryptedRequestBody = this.encryptAesCtr(requestBody, this.aesKey);

            // Build the HTTP request
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .header("Content-Type", "text/plain")
                    .header("Origin-Type", this.originType)
                    .header("Connection-Id", this.connectionId)
                    .POST(HttpRequest.BodyPublishers.ofString(new String(encryptedRequestBody)))
                    .build();

            // Get response
            HttpResponse<String> response = this.client.send(request, HttpResponse.BodyHandlers.ofString());

            // Get respone body
            String responseBody = response.body();

            Map<String, String> jsonMap;

            // Error if not successful
            if(response.statusCode() != 200){
                jsonMap = this.objectMapper.readValue(responseBody, Map.class);
                throw new RuntimeException(jsonMap.get("error"));
            }

            // Decrypt response
            byte[] decryptedCipher = this.decryptAesCtr(responseBody, this.aesKey);

            String decryptedString = new String(decryptedCipher, StandardCharsets.UTF_8);

            // Read response as JSON
            jsonMap = this.objectMapper.readValue(decryptedString, Map.class);

            // Extract presigned URL attribute from JSON response
            String presignedUrl = jsonMap.get("presignedUrl");

            // Use presigned URL to upload (PUT) \\

            boolean fail = false;

            String Etag = "";

            // Atttempt upload 3 times
            for(int i = 0; i < 3; i ++){
                // Build the HTTP request
                HttpRequest uploadRequest = HttpRequest.newBuilder()
                        .uri(URI.create(presignedUrl))
                        .PUT(HttpRequest.BodyPublishers.ofByteArray(baos))
                        .build();

                // Get upload response
                HttpResponse<String> uploadResponse = this.client.send(uploadRequest, HttpResponse.BodyHandlers.ofString());

                // Fail if not successful
                if(uploadResponse.statusCode() != 200){
                    // Set fail to true and try again
                    fail = true;
                }else{
                    // Extract ETag header
                    Optional<String> eTagHeader = uploadResponse.headers().firstValue("ETag");

                    if(eTagHeader.isPresent()){
                        Etag = eTagHeader.get();
                        break;
                    }else{
                        // ETag not present, try again
                        fail = true;
                    }
                }

            }

            // If failed after 3 attempts, throw error
            if(fail){
                throw new RuntimeException("Upload failed after 3 attempts. Try again later.");
            }

            // Return ETag
            return Etag;

        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("Upload part failed: " + e.getMessage(), e);
        }
    }

    /**
     * Use QIDO-RS to retrieve instance URLs
     * @param dicomWebBaseUrl Base URL of the DICOMweb server
     * @param studyInstanceUID Unique Study Instance UID of the study to be retrieved.
     * @param username Username for basic authentication
     * @param password Password for basic authentication
     * @return List of instance URIs
     */
    private static List<String> queryInstances(String dicomWebBaseUrl, String studyInstanceUID, String username, String password) throws Exception {
        List<String> sopInstanceUIDs = new ArrayList<>();

        // Build the URI for the QIDO-RS query
        String qidoUriStr = dicomWebBaseUrl + "/studies/" + studyInstanceUID + "/instances";
        URI qidoUri = new URI(qidoUriStr);

        // Create an HTTP client
        HttpClient client = HttpClient.newHttpClient();

        // Create an HTTP request
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(qidoUri)
                .header("Accept", "application/dicom+json")
                .GET();

        // Set basic authentication if needed
        if (username != null && password != null) {
            String auth = username + ":" + password;
            String encodedAuth = java.util.Base64.getEncoder().encodeToString(auth.getBytes());
            requestBuilder.header("Authorization", "Basic " + encodedAuth);
        }

        HttpRequest request = requestBuilder.build();

        // Send the request and get the response
        HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());

        if (response.statusCode() == 200) {

            // Parse the JSON response using Jackson's ObjectMapper
            InputStream jsonResponseStream = response.body();
            ObjectMapper objectMapper = new ObjectMapper();

            List<Map<String, Object>> dicomInstances = objectMapper.readValue(
                    jsonResponseStream,
                    new TypeReference<List<Map<String, Object>>>() {}
            );

            for (Map<String, Object> instance : dicomInstances) {
                Map<String, Object> sopInstanceMap = (Map<String, Object>) instance.get("00081190");
                if (sopInstanceMap != null) {
                    List<String> values = (List<String>) sopInstanceMap.get("Value");
                    if (values != null && !values.isEmpty()) {
                        String sopInstanceUID = values.get(0);
                        sopInstanceUIDs.add(sopInstanceUID);
                    }
                }
            }
        } else {
            throw new RuntimeException("Failed to query instances. HTTP error code: " + response.statusCode());
        }

        return sopInstanceUIDs;
    }

    /**
     * Use WADO-RS to retrieve the raw data for each instance
     * @param wadoUriStr URI for the instance
     * @param username Username for basic authentication
     * @param password Password for basic authentication
     * @return Raw content of each the instance
     */
    private static byte[] retrieveInstanceBytes(String wadoUriStr, String username, String password) throws Exception {
        // Build the URI for WADO-RS to retrieve the instance
        URI wadoUri = new URI(wadoUriStr);

        // Create an HTTP client
        HttpClient client = HttpClient.newHttpClient();

        // Create an HTTP request
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(wadoUri)
                .header("Accept", "multipart/related; type=application/dicom") //TODO: FIX THIS (something with mulipart and dicom)
                .GET();

        // Set basic authentication if needed
        if (username != null && password != null) {
            String auth = username + ":" + password;
            String encodedAuth = java.util.Base64.getEncoder().encodeToString(auth.getBytes());
            requestBuilder.header("Authorization", "Basic " + encodedAuth);
        }

        HttpRequest request = requestBuilder.build();

        // Send the request and get the response
        HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());

        if (response.statusCode() == 200) {
            String contentType = response.headers().firstValue("Content-Type").orElse("");
            String boundary = null;

            // Extract boundary from Content-Type header
            for (String param : contentType.split(";")) {
                param = param.trim();
                if (param.startsWith("boundary=")) {
                    boundary = param.substring("boundary=".length());
                    break;
                }
            }

            if (boundary == null) {
                throw new RuntimeException("Boundary not found in Content-Type header");
            }

            // Create a MimeMultipart object
            MimeMultipart multipart = new MimeMultipart(new ByteArrayDataSource(response.body(), contentType));

            // Iterate through the parts to find the DICOM part
            for (int i = 0; i < multipart.getCount(); i++) {
                BodyPart part = multipart.getBodyPart(i);
                String partContentType = part.getContentType();
                if (partContentType.toLowerCase().startsWith("application/dicom")) {
                    try (InputStream dicomStream = part.getInputStream();
                         ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

                        byte[] buffer = new byte[8192];
                        int len;
                        while ((len = dicomStream.read(buffer)) > 0) {
                            baos.write(buffer, 0, len);
                        }

                        return baos.toByteArray();
                    }
                }
            }

            throw new RuntimeException("No application/dicom part found in the multipart response");
        }else{
            System.err.println("Error retrieving instance" + ": HTTP error code " + response.statusCode());
            return null;
        }
    }

//    Public methods

    /**
     * Create a session with neuropacs application
     * @return Connection object (timestamp, connectionId, aesKey)
     */
    public String connect(){
        try{
            // Generate AES key for session
            String aes_key = this.generateAesKey();

            // Build URI
            URI uri = URI.create(this.serverUrl + "/api/connect/");

            // Build request body
            String requestBody = String.format("{ \"aes_key\": \"%s\" }", aes_key);

            // OAEP encrypt requuest body
            String encryptedBody = this.oaepEncrypt(requestBody);

            // Build the HTTP request
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .header("Content-Type", "text/plain")
                    .header("Origin-Type", this.originType)
                    .header("X-Api-Key", this.apiKey)
                    .POST(HttpRequest.BodyPublishers.ofString(encryptedBody))
                    .build();

            // Send request
            HttpResponse<String> response = this.client.send(request, HttpResponse.BodyHandlers.ofString());

            // Generate map from JSON response
            Map<String, String> jsonMap = this.objectMapper.readValue(response.body(), Map.class);

            // Error if not successful
            if(response.statusCode() != 200){
                throw new RuntimeException(jsonMap.get("error"));
            }

            // Return connection object
            String connectionId = jsonMap.get("connectionId");
            this.connectionId = connectionId;
            String timestamp = this.generateUTCTimeString();

            return String.format("{ \"timestamp\": \"%s\", \"connectionId\": \"%s\", \"aesKey\": \"%s\"  }", timestamp, connectionId, this.aesKey);
        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("Connection creation failed: " + e.getMessage(), e);
        }
    }

    /**
     * Create a new neuropacs order
     * @return Unique base64 identifier for the order.
     */
    public String newJob(){
        try{
            if(this.connectionId == null || this.aesKey == null){
                throw new RuntimeException("Missing session parameters, start a new session with 'connect()' and try again.");
            }

            // Build URI
            URI uri = URI.create(this.serverUrl + "/api/newJob/");

            // Build the HTTP request
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .header("Content-Type", "text/plain")
                    .header("Origin-Type", this.originType)
                    .header("Connection-Id", this.connectionId)
                    .GET()
                    .build();

            // Get response
            HttpResponse<String> response = this.client.send(request, HttpResponse.BodyHandlers.ofString());
            String responseBody = response.body();

            Map<String, String> jsonMap;

            // Error if not successful
            if(response.statusCode() != 201){
                jsonMap = this.objectMapper.readValue(responseBody, Map.class);
                throw new RuntimeException(jsonMap.get("error"));
            }

            // Decrypt response
            byte[] decryptedCipher = this.decryptAesCtr(responseBody, this.aesKey);
            String decryptedString = new String(decryptedCipher, StandardCharsets.UTF_8);

            // Parse response to JSON object
            jsonMap = this.objectMapper.readValue(decryptedString, Map.class);

            // Return orderId attribute from JSON response
            return jsonMap.get("orderId");

        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("Job creation failed: " + e.getMessage(), e);
        }
    }

    /**
     * Upload a dataset from a file path with callback
     * @param orderId Unique base64 identifier for the order.
     * @param datasetPath Path to dataset folder to be uploaded (ex. "/path/to/dicom").
     * @param callback Callback function invoked with upload progress.
     * @return Boolean indicating upload status.
     */
    public boolean uploadDatasetFromPath(String orderId, String datasetPath, Consumer<String> callback){
        try{
            if(this.connectionId == null || this.aesKey == null){
                throw new RuntimeException("Missing session parameters, start a new session with 'connect()' and try again.");
            }

            // Check if datasetPath exists and is a directory
            Path directoryPath = Paths.get(datasetPath);
            if (!Files.exists(directoryPath) || !Files.isDirectory(directoryPath)) {
                throw new RuntimeException("datasetPath does not exist.");
            }

            // Calculate total number of files in folder
            long totalFiles = Files.walk(directoryPath)
                    .parallel()
                    .filter(p -> !p.toFile().isDirectory() && !p.getFileName().toString().equals(".DS_Store"))
                    .count();

            // Hash set to hold unique filenames (cannot have repeats)
            Set<String> uniqueFilenames = new HashSet<>();

            int partIndex = 1; // Counts index of zip file
            int filesUploaded = 0; // Track number of files uploaded

            // Byte stream to hold zip contents
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            // Create ZipOutputStream wrapping the ByteArrayOutputStream
            ZipOutputStream zos = new ZipOutputStream(byteArrayOutputStream);

            // Collect all files to be processed
            List<Path> filesList = Files.walk(directoryPath)
                    .filter(p -> Files.isRegularFile(p) && !p.getFileName().toString().equals(".DS_Store"))
                    .toList();

            // Iterate through files in dataset
            for (Path file : filesList) {
                // Check if file is readable
                if (!Files.isReadable(file)) {
                    throw new RuntimeException("File is not readable.");
                }

                // Get filename
                String filename = file.getFileName().toString();

                // Get file size
                long fileSize = Files.size(file);

                // Get a unique filename
                String uniqueFilename = this.ensureUniqueFilename(uniqueFilenames, filename);

                // Add unique filename to list
                uniqueFilenames.add(uniqueFilename);

                // If zip size is large than max allowed, process
                byte[] zipContents = byteArrayOutputStream.toByteArray();

                if (zipContents.length > this.maxZipSize) {
                    // Close the current ZipOutputStream to finalize the ZIP file
                    zos.close();

                    // Calculate zip index
                    int zipIndex = partIndex - 1;

                    // Start new multipart upload
                    String uploadId = this.newMultipartUpload(orderId, zipIndex, orderId);

                    // Upload contents and extract ETag
                    String Etag = this.uploadMultipartChunk(uploadId, orderId, zipIndex, orderId, zipIndex + 1, zipContents);

                    // Add to final part map
                    List<Map<String, String>> finalParts = new ArrayList<>();
                    Map<String, String> part = new HashMap<>();
                    part.put("PartNumber", String.valueOf(zipIndex + 1));
                    part.put("ETag", Etag);
                    finalParts.add(part);

                    // Complete multipart upload
                    this.completeMultipartUpload(orderId, orderId, zipIndex, uploadId, finalParts);

                    // Reset the ByteArrayOutputStream
                    byteArrayOutputStream.reset();

                    // Create a new ZipOutputStream
                    zos = new ZipOutputStream(byteArrayOutputStream);

                    // Increment part index
                    partIndex++;
                }

                // Add the current file to the zip
                ZipEntry zipEntry = new ZipEntry(uniqueFilename);
                zos.putNextEntry(zipEntry);
                // Read and write file content
                try (InputStream is = Files.newInputStream(file)) {
                    byte[] buffer = new byte[8192];
                    int len;
                    while ((len = is.read(buffer)) > 0) {
                        zos.write(buffer, 0, len);
                    }
                }
                zos.closeEntry();

                // Increment files uploaded
                filesUploaded++;

                // Invoke callback
                float callbackStatus = ((float) filesUploaded/ (float) totalFiles)*100;
                String callbackStatusStr = String.format("%.2f", callbackStatus);
                if(callbackStatusStr.equals("100.00")){
                    callbackStatusStr = "100";
                }
                callback.accept("{orderId: " + orderId + ", progress: " + callbackStatusStr + ", status: " + "Uploading file " + filesUploaded + "/" + totalFiles + "}");
            }

            // Include remaining files (if existing open zip stream)
            byte[] zipContents = byteArrayOutputStream.toByteArray();
            if(zipContents.length > 0){
                // Close the ZipOutputStream to finalize the ZIP file
                zos.close();

                // Calculate zip index
                int zipIndex = partIndex - 1;

                // Start new multipart upload
                String uploadId = this.newMultipartUpload(orderId, zipIndex, orderId);

                // Upload contents and extract ETag
                String Etag = this.uploadMultipartChunk(uploadId, orderId, zipIndex, orderId, zipIndex+1, zipContents);

                // Add to final part map
                List<Map<String, String>> finalParts = new ArrayList<>();
                Map<String, String> part = new HashMap<>();
                part.put("PartNumber", String.valueOf(zipIndex+1));
                part.put("ETag", Etag);
                finalParts.add(part);

                // Complete multipart upload
                this.completeMultipartUpload(orderId, orderId, zipIndex, uploadId, finalParts);
            }else{
                // Close the ZipOutputStream if it's not already closed
                zos.close();
            }

            // Close the ByteArrayOutputStream
            byteArrayOutputStream.close();

            return true;
        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("Failed to upload dataset from path: " + e.getMessage(), e);
        }
    }


    /**
     * Upload a dataset from a file path
     * @param orderId Unique base64 identifier for the order.
     * @param datasetPath Path to dataset folder to be uploaded (ex. "/path/to/dicom").
     * @return Boolean indicating upload status.
     */
    public boolean uploadDatasetFromPath(String orderId, String datasetPath){
        try{
            if(this.connectionId == null || this.aesKey == null){
                throw new RuntimeException("Missing session parameters, start a new session with 'connect()' and try again.");
            }

            // Check if datasetPath exists and is a directory
            Path directoryPath = Paths.get(datasetPath);
            if (!Files.exists(directoryPath) || !Files.isDirectory(directoryPath)) {
                throw new RuntimeException("datasetPath does not exist.");
            }

            // Calculate total number of files in folder
            long totalFiles = Files.walk(directoryPath)
                    .parallel()
                    .filter(p -> !p.toFile().isDirectory() && !p.getFileName().toString().equals(".DS_Store"))
                    .count();

            // Hash set to hold unique filenames (cannot have repeats)
            Set<String> uniqueFilenames = new HashSet<>();

            int partIndex = 1; // Counts index of zip file
            int filesUploaded = 0; // Track number of files uploaded

            // Byte stream to hold zip contents
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            // Create ZipOutputStream wrapping the ByteArrayOutputStream
            ZipOutputStream zos = new ZipOutputStream(byteArrayOutputStream);

            // Collect all files to be processed
            List<Path> filesList = Files.walk(directoryPath)
                    .filter(p -> Files.isRegularFile(p) && !p.getFileName().toString().equals(".DS_Store"))
                    .toList();

            // Iterate through files in dataset
            for (Path file : filesList) {
                // Check if file is readable
                if (!Files.isReadable(file)) {
                    throw new RuntimeException("File is not readable.");
                }

                // Get filename
                String filename = file.getFileName().toString();

                // Get file size
                long fileSize = Files.size(file);

                // Get a unique filename
                String uniqueFilename = this.ensureUniqueFilename(uniqueFilenames, filename);

                // Add unique filename to list
                uniqueFilenames.add(uniqueFilename);

                // If zip size is large than max allowed, process
                byte[] zipContents = byteArrayOutputStream.toByteArray();
                if (zipContents.length > this.maxZipSize) {
                    // Close the current ZipOutputStream to finalize the ZIP file
                    zos.close();

                    // Calculate zip index
                    int zipIndex = partIndex - 1;

                    // Start new multipart upload
                    String uploadId = this.newMultipartUpload(orderId, zipIndex, orderId);

                    // Upload contents and extract ETag
                    String Etag = this.uploadMultipartChunk(uploadId, orderId, zipIndex, orderId, zipIndex + 1, zipContents);

                    // Add to final part map
                    List<Map<String, String>> finalParts = new ArrayList<>();
                    Map<String, String> part = new HashMap<>();
                    part.put("PartNumber", String.valueOf(zipIndex + 1));
                    part.put("ETag", Etag);
                    finalParts.add(part);

                    // Complete multipart upload
                    this.completeMultipartUpload(orderId, orderId, zipIndex, uploadId, finalParts);

                    // Reset the ByteArrayOutputStream
                    byteArrayOutputStream.reset();

                    // Create a new ZipOutputStream
                    zos = new ZipOutputStream(byteArrayOutputStream);

                    // Increment part index
                    partIndex++;
                }

                // Add the current file to the zip
                ZipEntry zipEntry = new ZipEntry(uniqueFilename);
                zos.putNextEntry(zipEntry);
                // Read and write file content
                try (InputStream is = Files.newInputStream(file)) {
                    byte[] buffer = new byte[8192];
                    int len;
                    while ((len = is.read(buffer)) > 0) {
                        zos.write(buffer, 0, len);
                    }
                }
                zos.closeEntry();

                // Increment files uploaded
                filesUploaded++;
            }

            // Include remaining files (if existing open zip stream)
            byte[] zipContents = byteArrayOutputStream.toByteArray();
            if(zipContents.length > 0){
                // Close the ZipOutputStream to finalize the ZIP file
                zos.close();

                // Calculate zip index
                int zipIndex = partIndex - 1;

                // Start new multipart upload
                String uploadId = this.newMultipartUpload(orderId, zipIndex, orderId);

                // Upload contents and extract ETag
                String Etag = this.uploadMultipartChunk(uploadId, orderId, zipIndex, orderId, zipIndex+1, zipContents);

                // Add to final part map
                List<Map<String, String>> finalParts = new ArrayList<>();
                Map<String, String> part = new HashMap<>();
                part.put("PartNumber", String.valueOf(zipIndex+1));
                part.put("ETag", Etag);
                finalParts.add(part);

                // Complete multipart upload
                this.completeMultipartUpload(orderId, orderId, zipIndex, uploadId, finalParts);
            }else{
                // Close the ZipOutputStream if it's not already closed
                zos.close();
            }

            // Close the ByteArrayOutputStream
            byteArrayOutputStream.close();

            return true;
        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("Failed to upload dataset from path: " + e.getMessage(), e);
        }
    }


    /**
     * Upload a dataset from DICOMweb with callback
     * @param orderId Unique base64 identifier for the order.
     * @param dicomWebBaseUrl Base URL of the DICOMweb server (e.g., 'http://localhost:8080/dcm4chee-arc/aets/DCM4CHEE/rs').
     * @param studyUid Unique Study Instance UID of the study to be retrieved.
     * @param username Username for basic authentication (use 'null' if not required)
     * @param password Password for basic authentication (use 'null' if not required)
     * @param callback Callback function invoked with upload progress.
     * @return Boolean indicating upload status.
     */
    public boolean uploadDatasetFromDicomWeb(String orderId, String dicomWebBaseUrl, String studyUid, String username, String password, Consumer<String> callback){
        try {
            if(this.connectionId == null || this.aesKey == null){
                throw new RuntimeException("Missing session parameters, start a new session with 'connect()' and try again.");
            }
            // Use QIDO-RS to get list of SOP Instance UIDs
            List<String> sopInstanceURIs = queryInstances(dicomWebBaseUrl, studyUid, username, password);

            int totalFiles = sopInstanceURIs.size();

            int partIndex = 1; // Counts index of zip file
            int filesUploaded = 0; // Track number of files uploaded

            // Byte stream to hold zip contents
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            // Create ZipOutputStream wrapping the ByteArrayOutputStream
            ZipOutputStream zos = new ZipOutputStream(byteArrayOutputStream);

            // Use WADO-RS to retrieve each instance and get bytes
            for (String sopInstanceURI : sopInstanceURIs) {
                byte[] instanceBytes = retrieveInstanceBytes(sopInstanceURI, username, password);
                if (instanceBytes != null) {
                    // Get filename
                    String filename = this.generateUniqueUUID();

                    // Get file size
                    long fileSize = instanceBytes.length;

                    // If zip size is large than max allowed, process
                    byte[] zipContents = byteArrayOutputStream.toByteArray();
                    if (zipContents.length > this.maxZipSize) {
                        // Close the current ZipOutputStream to finalize the ZIP file
                        zos.close();

                        // Calculate zip index
                        int zipIndex = partIndex - 1;

                        // Start new multipart upload
                        String uploadId = this.newMultipartUpload(orderId, zipIndex, orderId);

                        // Upload contents and extract ETag
                        String Etag = this.uploadMultipartChunk(uploadId, orderId, zipIndex, orderId, zipIndex + 1, zipContents);

                        // Add to final part map
                        List<Map<String, String>> finalParts = new ArrayList<>();
                        Map<String, String> part = new HashMap<>();
                        part.put("PartNumber", String.valueOf(zipIndex + 1));
                        part.put("ETag", Etag);
                        finalParts.add(part);

                        // Complete multipart upload
                        this.completeMultipartUpload(orderId, orderId, zipIndex, uploadId, finalParts);

                        // Reset the ByteArrayOutputStream
                        byteArrayOutputStream.reset();

                        // Create a new ZipOutputStream
                        zos = new ZipOutputStream(byteArrayOutputStream);

                        // Reset current zip file size
                        curZipSize = 0;

                        // Increment part index
                        partIndex++;
                    }

                    // Add the current file to the zip
                    ZipEntry zipEntry = new ZipEntry(filename);
                    zos.putNextEntry(zipEntry);

                    zos.write(instanceBytes);

                    zos.closeEntry();

                    // Increment files uploaded
                    filesUploaded++;

                    // Invoke callback
                    float callbackStatus = ((float) filesUploaded/ (float) totalFiles)*100;
                    String callbackStatusStr = String.format("%.2f", callbackStatus);
                    if(callbackStatusStr.equals("100.00")){
                        callbackStatusStr = "100";
                    }
                    callback.accept("{orderId: " + orderId + ", progress: " + callbackStatusStr + ", status: " + "Uploading file " + filesUploaded + "/" + totalFiles + "}");
                }
            }

            // Include remaining files (if existing open zip stream)
            byte[] zipContents = byteArrayOutputStream.toByteArray();
            if(zipContents.length > 0){
                // Close the ZipOutputStream to finalize the ZIP file
                zos.close();

                // Calculate zip index
                int zipIndex = partIndex - 1;

                // Start new multipart upload
                String uploadId = this.newMultipartUpload(orderId, zipIndex, orderId);

                // Upload contents and extract ETag
                String Etag = this.uploadMultipartChunk(uploadId, orderId, zipIndex, orderId, zipIndex+1, zipContents);

                // Add to final part map
                List<Map<String, String>> finalParts = new ArrayList<>();
                Map<String, String> part = new HashMap<>();
                part.put("PartNumber", String.valueOf(zipIndex+1));
                part.put("ETag", Etag);
                finalParts.add(part);

                // Complete multipart upload
                this.completeMultipartUpload(orderId, orderId, zipIndex, uploadId, finalParts);
            }else{
                // Close the ZipOutputStream if it's not already closed
                zos.close();
            }
            // Close the ByteArrayOutputStream
            byteArrayOutputStream.close();

            return true;
        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("Failed to upload dataset from path: " + e.getMessage(), e);
        }
    }

    /**
     * Upload a dataset from DICOMweb
     * @param orderId Unique base64 identifier for the order.
     * @param dicomWebBaseUrl Base URL of the DICOMweb server (e.g., 'http://localhost:8080/dcm4chee-arc/aets/DCM4CHEE/rs').
     * @param studyUid Unique Study Instance UID of the study to be retrieved.
     * @param username Username for basic authentication (use 'null' if not required)
     * @param password Password for basic authentication (use 'null' if not required)
     * @return Boolean indicating upload status.
     */
    public boolean uploadDatasetFromDicomWeb(String orderId, String dicomWebBaseUrl, String studyUid, String username, String password){
        try {
            if(this.connectionId == null || this.aesKey == null){
                throw new RuntimeException("Missing session parameters, start a new session with 'connect()' and try again.");
            }
            // Use QIDO-RS to get list of SOP Instance UIDs
            List<String> sopInstanceURIs = queryInstances(dicomWebBaseUrl, studyUid, username, password);

            int totalFiles = sopInstanceURIs.size();

            int partIndex = 1; // Counts index of zip file
            int filesUploaded = 0; // Track number of files uploaded
            long curZipSize = 0; // Track current zip size

            // Byte stream to hold zip contents
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            // Create ZipOutputStream wrapping the ByteArrayOutputStream
            ZipOutputStream zos = new ZipOutputStream(byteArrayOutputStream);

            // Use WADO-RS to retrieve each instance and get bytes
            for (String sopInstanceURI : sopInstanceURIs) {
                byte[] instanceBytes = retrieveInstanceBytes(sopInstanceURI, username, password);
                if (instanceBytes != null) {
                    // Get filename
                    String filename = this.generateUniqueUUID();

                    // Get file size
                    long fileSize = instanceBytes.length;

                    // If zip size is large than max allowed, process
                    byte[] zipContents = byteArrayOutputStream.toByteArray();
                    if (zipContents.length > this.maxZipSize) {
                        // Close the current ZipOutputStream to finalize the ZIP file
                        zos.close();

                        // Calculate zip index
                        int zipIndex = partIndex - 1;

                        // Start new multipart upload
                        String uploadId = this.newMultipartUpload(orderId, zipIndex, orderId);

                        // Upload contents and extract ETag
                        String Etag = this.uploadMultipartChunk(uploadId, orderId, zipIndex, orderId, zipIndex + 1, zipContents);

                        // Add to final part map
                        List<Map<String, String>> finalParts = new ArrayList<>();
                        Map<String, String> part = new HashMap<>();
                        part.put("PartNumber", String.valueOf(zipIndex + 1));
                        part.put("ETag", Etag);
                        finalParts.add(part);

                        // Complete multipart upload
                        this.completeMultipartUpload(orderId, orderId, zipIndex, uploadId, finalParts);

                        // Reset the ByteArrayOutputStream
                        byteArrayOutputStream.reset();

                        // Create a new ZipOutputStream
                        zos = new ZipOutputStream(byteArrayOutputStream);

                        // Increment part index
                        partIndex++;
                    }

                    // Add the current file to the zip
                    ZipEntry zipEntry = new ZipEntry(filename);
                    zos.putNextEntry(zipEntry);

                    zos.write(instanceBytes);

                    zos.closeEntry();

                    // Increment files uploaded
                    filesUploaded++;
                }
            }

            // Include remaining files (if existing open zip stream)
            byte[] zipContents = byteArrayOutputStream.toByteArray();
            if(zipContents.length > 0){
                // Close the ZipOutputStream to finalize the ZIP file
                zos.close();

                // Calculate zip index
                int zipIndex = partIndex - 1;

                // Start new multipart upload
                String uploadId = this.newMultipartUpload(orderId, zipIndex, orderId);

                // Upload contents and extract ETag
                String Etag = this.uploadMultipartChunk(uploadId, orderId, zipIndex, orderId, zipIndex+1, zipContents);

                // Add to final part map
                List<Map<String, String>> finalParts = new ArrayList<>();
                Map<String, String> part = new HashMap<>();
                part.put("PartNumber", String.valueOf(zipIndex+1));
                part.put("ETag", Etag);
                finalParts.add(part);

                // Complete multipart upload
                this.completeMultipartUpload(orderId, orderId, zipIndex, uploadId, finalParts);
            }else{
                // Close the ZipOutputStream if it's not already closed
                zos.close();
            }
            // Close the ByteArrayOutputStream
            byteArrayOutputStream.close();

            return true;
        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("Failed to upload dataset from path: " + e.getMessage(), e);
        }
    }


    /**
     * Run an order
     * @param orderId Unique base64 identifier for the order.
     * @param productName Name of product to be executed
     * @return Response code of request
     */
    public int runJob(String orderId, String productName){
        try{
            if(this.connectionId == null || this.aesKey == null){
                throw new RuntimeException("Missing session parameters, start a new session with 'connect()' and try again.");
            }
            // Build URI
            URI uri = URI.create(this.serverUrl + "/api/runJob/");

            // Build request body
            String requestBody = String.format("{ \"productName\": \"%s\", \"orderId\": \"%s\" }", productName, orderId);

            // Encrypt request body
            byte[] encryptedBody = this.encryptAesCtr(requestBody, this.aesKey);

            // Build the HTTP request
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .header("Content-Type", "text/plain")
                    .header("Origin-Type", this.originType)
                    .header("Connection-Id", this.connectionId)
                    .POST(HttpRequest.BodyPublishers.ofString(new String(encryptedBody)))
                    .build();

            // Get response
            HttpResponse<String> response = this.client.send(request, HttpResponse.BodyHandlers.ofString());
            String responseBody = response.body();

            Map<String, String> jsonMap;

            // Error if not successful
            if(response.statusCode() != 202){
                jsonMap = this.objectMapper.readValue(responseBody, Map.class);
                throw new RuntimeException(jsonMap.get("error"));
            }

            return response.statusCode();

        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("Job run failed: " + e.getMessage(), e);
        }
    }

    /**
     * Check job status for a specified order
     * @param orderId Unique base64 identifier for the order.
     * @return Job status message in JSON.
     */
    public String checkStatus(String orderId){
        try{
            if(this.connectionId == null || this.aesKey == null){
                throw new RuntimeException("Missing session parameters, start a new session with 'connect()' and try again.");
            }
            // Build URI
            URI uri = URI.create(this.serverUrl + "/api/checkStatus/");

            // Build request body
            String requestBody = String.format("{ \"orderId\": \"%s\" }", orderId);

            // Encrypt request body
            byte[] encryptedBody = this.encryptAesCtr(requestBody, this.aesKey);

            // Build the HTTP request
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .header("Content-Type", "text/plain")
                    .header("Origin-Type", this.originType)
                    .header("Connection-Id", this.connectionId)
                    .POST(HttpRequest.BodyPublishers.ofString(new String(encryptedBody)))
                    .build();

            // Get response
            HttpResponse<String> response = this.client.send(request, HttpResponse.BodyHandlers.ofString());
            String responseBody = response.body();

            Map<String, String> jsonMap;

            // Error if not successful
            if(response.statusCode() != 200){
                jsonMap = this.objectMapper.readValue(responseBody, Map.class);
                throw new RuntimeException(jsonMap.get("error"));
            }

            // Return decrypted response string
            byte[] decryptedCipher = this.decryptAesCtr(responseBody, this.aesKey);
            return new String(decryptedCipher, StandardCharsets.UTF_8);

        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("Status check failed: " + e.getMessage(), e);
        }
    }

    /**
     * Get job results for a specified order in a specified format
     * @param orderId Unique base64 identifier for the order.
     * @param format Format of file data ('txt'/'xml'/'json'/'png')
     * @return  Result string in specified format
     */
    public String getResults(String orderId, String format){
        try{
            if(this.connectionId == null || this.aesKey == null){
                throw new RuntimeException("Missing session parameters, start a new session with 'connect()' and try again.");
            }
            // Build URI
            URI uri = URI.create(this.serverUrl + "/api/getResults/");

            // Set result string to lowercase
            format = format.toLowerCase();

            // Check if format is valid
            String[] allowedFormats = {"xml", "json", "txt"};
            if(!Arrays.asList(allowedFormats).contains(format)){
                throw new RuntimeException("Invalid format. Valid formats include: \"txt\", \"json\", \"xml\".");
            }

            // Build request body
            String requestBody = String.format("{ \"orderId\": \"%s\", \"format\": \"%s\" }", orderId, format);

            // Encrypt request body
            byte[] encryptedBody = this.encryptAesCtr(requestBody, this.aesKey);

            // Build the HTTP request
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .header("Content-Type", "text/plain")
                    .header("Origin-Type", this.originType)
                    .header("Connection-Id", this.connectionId)
                    .POST(HttpRequest.BodyPublishers.ofString(new String(encryptedBody)))
                    .build();

            // Get response
            HttpResponse<String> response = this.client.send(request, HttpResponse.BodyHandlers.ofString());
            String responseBody = response.body();

            Map<String, String> jsonMap;

            // Error if not successful
            if(response.statusCode() != 200){
                jsonMap = this.objectMapper.readValue(responseBody, Map.class);
                throw new RuntimeException(jsonMap.get("error"));
            }

            // Return decrypted response body
            byte[] decryptedCipher = this.decryptAesCtr(responseBody, this.aesKey);
            return new String(decryptedCipher, StandardCharsets.UTF_8);

        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("Status check failed: " + e.getMessage(), e);
        }
    }

    /**
     * Get results of existing neuropacs order in PNG (byte[]) format
     * @param orderId Base64 orderId
     * @return  PNG contents in byte[] format
     */
    public byte[] getResultsPng(String orderId){
        try{
            if(this.connectionId == null || this.aesKey == null){
                throw new RuntimeException("Missing session parameters, start a new session with 'connect()' and try again.");
            }
            // Build URI
            URI uri = URI.create(this.serverUrl + "/api/getResults/");

            // Build request body
            String requestBody = String.format("{ \"orderId\": \"%s\", \"format\": \"%s\" }", orderId, "png");

            // Encrypt request body
            byte[] encryptedBody = this.encryptAesCtr(requestBody, this.aesKey);

            // Build the HTTP request
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .header("Content-Type", "text/plain")
                    .header("Origin-Type", this.originType)
                    .header("Connection-Id", this.connectionId)
                    .POST(HttpRequest.BodyPublishers.ofString(new String(encryptedBody)))
                    .build();

            // Get response
            HttpResponse<String> response = this.client.send(request, HttpResponse.BodyHandlers.ofString());
            String responseBody = response.body();

            Map<String, String> jsonMap;

            // Error if not successful
            if(response.statusCode() != 200){
                jsonMap = this.objectMapper.readValue(responseBody, Map.class);
                throw new RuntimeException(jsonMap.get("error"));
            }

            // Return decrypted response body byte[]
            return this.decryptAesCtr(responseBody, this.aesKey);

        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("Status check failed: " + e.getMessage(), e);
        }
    }
}
