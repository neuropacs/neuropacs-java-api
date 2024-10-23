/**
 * File: Neuropacs.java
 * Description: neuropacs Java API
 * Author: Kerrick Cavanaugh
 * Date Created: 09/15/2024
 * Last Updated: 09/30/2024
 *
 * ---------- Audit Log ---------- *
 * 09/15/2024 - Initial creation
 * 09/16/2024 - Implemented AES and OAEP encryption methods
 * 09/26/2024 - Added mulitpart upload functionality
 * 09/30/2024 - Completed core logic
 */

package org.neuropacs;

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
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

// Neuropacs class
public class Neuropacs {
    //    Private instance variables
    private String serverUrl;
    private String apiKey;
    private String originType;
    private String aesKey;
    private String orderId;
    private String connectionId;
    private long zipChunkSize = 50000000; // 5mb
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
     *  Zip dataset
     * @param sources   List of file paths to be zipped
     * @param zipFilenames  Corresponding list of file names to be zipped (maps to a source in sources)
     * @return  Zip contents in byte[] format
     * @throws IOException
     */
    private byte[] zipDataset(List<Path> sources, List<String> zipFilenames)
            throws IOException {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        try (ZipOutputStream zos = new ZipOutputStream(byteArrayOutputStream)) {
            int srcIndex = 0;
            // Iterate through sources list
            for (Path source : sources) {

                // Add each source to zip with corresponding name in zipFilenames
                ZipEntry zipEntry = new ZipEntry(zipFilenames.get(srcIndex));
                zos.putNextEntry(zipEntry);

                // Get all bytes (can overflow heap if contents too large - currently capped at 5MB)
                byte[] fileContent = Files.readAllBytes(source);

                // Write to output stream
                zos.write(fileContent, 0, fileContent.length);

                // Maybe better for performance rather than reading whole file at once
//                try (FileInputStream fis = new FileInputStream(source.toFile())) {
//                    byte[] buffer = new byte[4096];
//                    int len;
//                    while ((len = fis.read(buffer)) > 0) {
//                        zos.write(buffer, 0, len);
//                    }
//                }

                zos.closeEntry();
                srcIndex ++;
            }
        }
        // Return zip contents in byte[] format
        return byteArrayOutputStream.toByteArray();
    }

    /**
     *  Upload ZIP contents to S3 bucket using multipart upload
     * @param datasetDir    Directory (String) where dataset is located
     * @param orderId   Base64 orderId
     */
    private void uploadZipContents(String datasetDir, String orderId){
        try{
            Path datasetPath = Paths.get(datasetDir);

            // Calculate total number of files in folder
            long totalFiles = Files.walk(datasetPath)
                    .parallel()
                    .filter(p -> !p.toFile().isDirectory() && !p.getFileName().toString().equals(".DS_Store"))
                    .count();


            // Hash set to hold unique filenames (cannot have repeats)
            Set<String> uniqueFilenames = new HashSet<>();
            List<String> curZipFilenameList = new ArrayList<String>();
            List<Path> sources = new ArrayList<Path>();

            // Holds part data for multipart upload processing
            List<Map<String, String>> finalParts = new ArrayList<>();

            long curZipSize = 0; // Current size of zip file
            short totalParts = 0;
            short zipIndex = 0; // Index of zip file
            short filesProcessed = 0; // Total number of processed files (for callback)

            boolean finalFile = false;

            // Iterate through files in dataset
            try (Stream<Path> stream = Files.walk(datasetPath)) {
                for (Iterator<Path> it = stream.iterator(); it.hasNext(); ) {

                    Path file = it.next();

                    // Check if file is readible
                    if(!Files.isReadable(file)) {
                        throw new RuntimeException("File is not readable.");
                    }

                    // Flag final file (to capture last files)
                    if(!it.hasNext()){
                        finalFile = true;
                    }

                    // Extract filename
                    String filename = file.getFileName().toString();

                    // Ensure file is a file and exclude ".DS_Store"
                    if(Files.isDirectory(file) || filename.equals(".DS_Store")){
                        continue;
                    }

                    // Get a unique filename
                    String uniqueFilename = this.ensureUniqueFilename(uniqueFilenames, filename);

                    // Add unique filename to list
                    uniqueFilenames.add(uniqueFilename);

                    curZipFilenameList.add(uniqueFilename);

                    // Add file to soruces to be zipped
                    sources.add(file);

                    // Get size of file
                    long fileSize = Files.size(file);

                    // Increment cur zip file size
                    curZipSize += fileSize;

                    // If current zip file size is larger than the max zip chunk size or final file, enter block
                    if(curZipSize >= this.zipChunkSize || finalFile){

                        // Start new multipart upload
                        String uploadId = this.newMultipartUpload(orderId, zipIndex, orderId);

                        // Zip contents
                        byte[] baos = this.zipDataset(sources, curZipFilenameList);

                        //NOTE: Part numbers are obsolete if chunk size is same as part size

                        // Upload contents and extract ETag
                        String Etag = this.uploadMultipartChunk(uploadId, orderId, zipIndex, orderId, zipIndex+1, baos);

                        // Add to final part map
                        Map<String, String> part = new HashMap<>();
                        part.put("PartNumber", String.valueOf(zipIndex+1));
                        part.put("ETag", Etag);
                        finalParts.add(part);

                        // Complete multipart upload
                        this.completeMultipartUpload(orderId, orderId, zipIndex, uploadId, finalParts);

                        // Reset for next zip file
                        zipIndex ++;
                        curZipSize = 0;
                        curZipFilenameList.clear();
                        finalParts.clear();
                        sources.clear();
                    }

                    filesProcessed ++;

                    // Callback stuff here ("Processing")
                }
            }

        } catch (Exception e) {
            // Throw error
            throw new RuntimeException(e);
        }
    }

    /**
     *  Upload ZIP contents to S3 bucket using multipart upload with specified datasetId
     * @param datasetDir    Directory (String) where dataset is located
     * @param orderId   Base64 orderId
     * @param datasetId String to identify dataset (must be unique)
     */
    private void uploadZipContents(String datasetDir, String orderId, String datasetId){
        try{
            Path datasetPath = Paths.get(datasetDir);

            // Calculate total number of files in folder
            long totalFiles = Files.walk(datasetPath)
                    .parallel()
                    .filter(p -> !p.toFile().isDirectory() && !p.getFileName().toString().equals(".DS_Store"))
                    .count();


            // Hash set to hold unique filenames (cannot have repeats)
            Set<String> uniqueFilenames = new HashSet<>();
            List<String> curZipFilenameList = new ArrayList<String>();
            List<Path> sources = new ArrayList<Path>();

            // Holds part data for multipart upload processing
            List<Map<String, String>> finalParts = new ArrayList<>();

            long curZipSize = 0; // Current size of zip file
            short totalParts = 0;
            short zipIndex = 0; // Index of zip file
            short filesProcessed = 0; // Total number of processed files (for callback)

            boolean finalFile = false;

            // Iterate through files in dataset
            try (Stream<Path> stream = Files.walk(datasetPath)) {
                for (Iterator<Path> it = stream.iterator(); it.hasNext(); ) {

                    Path file = it.next();

                    // Check if file is readible
                    if(!Files.isReadable(file)) {
                        throw new RuntimeException("File is not readable.");
                    }

                    // Flag final file (to capture last files)
                    if(!it.hasNext()){
                        finalFile = true;
                    }

                    // Extract filename
                    String filename = file.getFileName().toString();

                    // Ensure file is a file and exclude ".DS_Store"
                    if(Files.isDirectory(file) || filename.equals(".DS_Store")){
                        continue;
                    }

                    // Get a unique filename
                    String uniqueFilename = this.ensureUniqueFilename(uniqueFilenames, filename);

                    // Add unique filename to list
                    uniqueFilenames.add(uniqueFilename);

                    curZipFilenameList.add(uniqueFilename);

                    // Add file to soruces to be zipped
                    sources.add(file);

                    // Get size of file
                    long fileSize = Files.size(file);

                    // Increment cur zip file size
                    curZipSize += fileSize;

                    // If current zip file size is larger than the max zip chunk size or final file, enter block
                    if(curZipSize >= this.zipChunkSize || finalFile){

                        // Start new multipart upload
                        String uploadId = this.newMultipartUpload(datasetId, zipIndex, orderId);

                        // Zip contents
                        byte[] baos = this.zipDataset(sources, curZipFilenameList);

                        //NOTE: Part numbers are obsolete if chunk size is same as part size

                        // Upload contents and extract ETag
                        String Etag = this.uploadMultipartChunk(uploadId, datasetId, zipIndex, orderId, zipIndex+1, baos);

                        // Add to final part map
                        Map<String, String> part = new HashMap<>();
                        part.put("PartNumber", String.valueOf(zipIndex+1));
                        part.put("ETag", Etag);
                        finalParts.add(part);

                        // Complete multipart upload
                        this.completeMultipartUpload(orderId, datasetId, zipIndex, uploadId, finalParts);

                        // Reset for next zip file
                        zipIndex ++;
                        curZipSize = 0;
                        curZipFilenameList.clear();
                        finalParts.clear();
                        sources.clear();
                    }

                    filesProcessed ++;

                    // Callback stuff here ("Processing")
                }
            }

        } catch (Exception e) {
            // Throw error
            throw new RuntimeException(e);
        }
    }

    /**
     * Start a new S3 multipart upload
     * @param datasetId Base64 datasetId (String)
     * @param zipIndex  Index of zip file
     * @param orderId   Base64 orderId (String)
     * @return  Upload Id correlating upload to S3 object
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
     * Attempt a dataset upload
     * @param datasetPath String path to dataset to be uploaded
     * @param orderId Base64 orderId
     * @param datasetId Base64 datasetId
     * @return 0 on success, 1 on failure
     */
    private int attemptUploadDataset(String datasetPath, String orderId, String datasetId){
        try{
            uploadZipContents(datasetPath, orderId);
            return 0;
        } catch (Exception e) {
            return 1;
        }
    }


//    Public methods

    /**
     * Create a connection with neuropacs application
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
     * @return Base64 orderId
     */
    public String newJob(){
        try{
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

//    /**
//     * Upload a dataset to the neuropacs S3 bucket
//     * @param datasetPath   Path to dataset (String)
//     * @param orderId   Base64 orderId
//     * @param datasetId Base 64 datasetId
//     * @param callback Progress callback
//     * @return 0 on success
//     */
//    public int uploadDataset(String datasetPath, String orderId, String datasetId, Callable<String> callback) {
//        try {
//            // Check if datasetPath exists
//            Path directoryPath = Paths.get(datasetPath);
//            if (!Files.exists(directoryPath) || !Files.isDirectory(directoryPath)) {
//                throw new RuntimeException("datasetPath does not exist.");
//            }
//
//            return 0;
//
//        } catch (Exception e) {
//            throw new RuntimeException("Dataset upload failed: " + e.getMessage(), e);
//
//        }
//    }


    /**
     * Upload a dataset to neuropacs S3 bucket
     * @param datasetPath Path to dataset (String)
     * @param orderId Base64 orderId
     * @return
     */
    public int uploadDataset(String datasetPath, String orderId){
        try {
            // Check if datasetPath exists and is a directory
            Path directoryPath = Paths.get(datasetPath);
            if (!Files.exists(directoryPath) || !Files.isDirectory(directoryPath)) {
                throw new RuntimeException("datasetPath does not exist.");
            }

            // Attempt upload dataset
            attemptUploadDataset(datasetPath, orderId, datasetPath);
            return 0;
        } catch (Exception e) {
            // Throw error
            throw new RuntimeException("Dataset upload failed: " + e.getMessage(), e);
        }
    }

    /**
     * Check status of existing neuropacs order
     * @param orderId Base64 orderId
     * @return  Status string
     */
    public String checkStatus(String orderId){
        try{
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
     *  Get results for existing neuropacs order
     * @param format    Format of results to be returned ('txt', 'json', 'xml')
     * @param orderId   Base64 orderId
     * @return  Result string in specified format
     */
    public String getResults(String format, String orderId){
        try{
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
