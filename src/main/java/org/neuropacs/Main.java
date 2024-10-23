package org.neuropacs;

//import javax.imageio.ImageIO;
//import java.awt.image.BufferedImage;
//import java.io.ByteArrayInputStream;
//import java.io.File;
//import java.io.IOException;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static void main(String[] args) {
        String serverUrl = "";
        String apiKey = ""; // DELETE THIS
        String originType = "Java";

        Neuropacs npcs = new Neuropacs(serverUrl, apiKey, originType);

        String connection = npcs.connect();
        System.out.println(connection);

        String order = npcs.newJob();
        System.out.println("New order: " + order);

        int upload = npcs.uploadDataset("/Users/kerrickcavanaugh/Desktop/sample data/06_011", order);

        String status = npcs.checkStatus("TEST");
        System.out.println(status);

        String results = npcs.getResults("json", "TEST");
        System.out.println(results);

        byte[] resultPng = npcs.getResultsPng("TEST");

        try {
            // Convert byte[] to BufferedImage
            BufferedImage img = generateImageFromBytes(resultPng);

            // Save the image to a file (optional)
            ImageIO.write(img, "png", new File("output_image.png"));

            System.out.println("Image generated and saved successfully.");
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static BufferedImage generateImageFromBytes(byte[] imageBytes) throws IOException {
        // Convert byte[] to an InputStream
        ByteArrayInputStream bais = new ByteArrayInputStream(imageBytes);

        // Read the input stream into a BufferedImage
        BufferedImage image = ImageIO.read(bais);

        // Check if the image was read correctly
        if (image == null) {
            throw new IOException("Could not decode image from the provided byte array.");
        }

        return image;
    }
}