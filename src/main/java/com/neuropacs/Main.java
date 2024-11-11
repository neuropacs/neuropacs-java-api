package com.neuropacs;
import com.neuropacs.Neuropacs;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
//import java.io.ByteArrayInpudtStream;
import java.io.File;
import java.io.IOException;

public class Main {
    public static void main(String[] args) {
        String serverUrl = "https://ud7cvn39n4.execute-api.us-east-1.amazonaws.com/sandbox";
        String apiKey = "generate_api_key"; //! DELETE THIS
        String originType = "Java Test";
        String productName = "Atypical/MSAp/PSP-v1.0";

        Neuropacs npcs = new Neuropacs(serverUrl, apiKey, originType);

        String connection = npcs.connect();
        System.out.println(connection);

        String order = npcs.newJob();
        System.out.println("New order: " + order);

//        boolean upload = npcs.uploadDatasetFromPath(order, "/Users/kerrickcavanaugh/Desktop/06_001", System.out::println);
//        System.out.println(upload);

        boolean uplaod = npcs.uploadDatasetFromDicomWeb(order, "http://localhost:8080/dcm4chee-arc/aets/DCM4CHEE/rs", "1.3.12.2.1107.5.2.32.35162.30000022041820573832300000043", null, null, System.out::println);
        System.out.println(uplaod);
//
//        int job = npcs.runJob(order, productName);
//        System.out.println(job);

//        String status = npcs.checkStatus("TEST");
//        System.out.println(status);
//
//        String results = npcs.getResults("json", "TEST");
//        System.out.println(results);

//        byte[] resultPng = npcs.getResultsPng("TEST");
//
//        try {
//            // Convert byte[] to BufferedImage
//            BufferedImage img = generateImageFromBytes(resultPng);
//
//            // Save the image to a file (optional)
//            ImageIO.write(img, "png", new File("output_image.png"));
//
//            System.out.println("Image generated and saved successfully.");
//        } catch (IOException e) {
//            e.printStackTrace();
//        }

    }

//    public static BufferedImage generateImageFromBytes(byte[] imageBytes) throws IOException {
//        // Convert byte[] to an InputStream
//        ByteArrayInputStream bais = new ByteArrayInputStream(imageBytes);
//
//        // Read the input stream into a BufferedImage
//        BufferedImage image = ImageIO.read(bais);
//
//        // Check if the image was read correctly
//        if (image == null) {
//            throw new IOException("Could not decode image from the provided byte array.");
//        }
//
//        return image;
//    }
}