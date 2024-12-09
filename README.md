![CodeQL](https://github.com/neuropacs/neuropacs-java-api/actions/workflows/codeql-analysis.yml/badge.svg)

# neuropacs™ Java API

Connect to neuropacs™ diagnostic capabilities with our Java API.

## Overview

Your software is 5 lines away from accurately diagnosing Parkinson's variations.

Neuropacs can differentiate three major Parkinsonisms (PD, MSA, and PSP) with [proven > 90% accuracy](https://neuropacs.com). We provide easy ways to integrate neuropacs™ into your medical software. Whether it is a diagnostic tool, PACS system, or medical image viewer, neuropacs™ can be easily integrated as a plugin.

This wiki provides comprehensive documentation for all integrations, supported languages, and technical details of our product.

The neuropacs™ system is a software application intended to receive and analyze diffusion MRI data from patients aged 40 years and older presenting with Parkinson's disease (PD) symptoms. The neuropacs™ system provides a report to aid neuroradiologists and/or neurologists in identifying patients with Atypical Parkinsonism (i.e., multiple system atrophy Parkinsonian variant (MSAp), or progressive supranuclear palsy (PSP)). The results of the neuropacs™ system are intended to provide supplemental information in conjunction with a standard neurological assessment and other clinical tests. **Patient management decisions should not be made solely on the basis of analysis by the neuropacs™ system.**

Visit our official [wiki](https://neuropacs.github.io) for more technical documentation.

## Getting Started

### Installation

Add the dependency to pom.xml

```xml
<dependency>
    <groupId>com.neuropacs</groupId>
    <artifactId>neuropacs-java-api</artifactId>
    <version>1.0.1</version>
</dependency>
```

Build the project

```shell
mvn clean install
```

### Usage

Initialization

```java
    // Import the neuropacs module
    import com.neuropacs.Neuropacs

    // Define neuropacs parameters
    String apiKey = "your_api_key"; // API key
    String serverUrl = "server_url"; // neuropacs™ serverl URL
    String productName = "Atypical/MSAp/PSP-v1.0"; // Desired neuropacs™ product
    String predictionFormat = "JSON"; // Output format of results
    String originType = "my_application"; // Requestor origin

    // Initialize the API
    Neuropacs npcs = new Neuropacs(serverUrl, apiKey, originType);
```

Example

```java
    // Create a session
    String conn = npcs.connect();

    // Create a new order
    String conn = npcs.newJob();

    // Upload a dataset from path
    boolean upload = npcs.uploadDatasetFromPath(orderId, "/path/to/dataset");

    // Start an order
    String orderStart = npcs.runJob(orderId, productName);

    // Check order status
    String status = npcs.checkStatus(orderId);

    // Retrieve job results
    String results = npcs.getResults(orderId, predictionFormat);

    // Retrieve job results in PNG
    byte[] resultsPng = npcs.getResultsPng(orderId);
```

Example viewing a PNG result

```java
    // Import required packages
    import javax.imageio.ImageIO;
    import java.awt.image.BufferedImage;
    import java.io.ByteArrayInpudtStream;
    import java.io.File;

    // Retrieve job results in PNG
    byte[] resultsPng = npcs.getResultsPng(orderId);

    // Convert byte[] to an InputStream
    ByteArrayInputStream bais = new ByteArrayInputStream(resultsPng);

    // Read the input stream into a BufferedImage
    BufferedImage image = ImageIO.read(bais);

    // Save the image to a file
    ImageIO.write(image, "png", new File("neuropacs_report.png"));
```

### DICOMweb WADO-RS Integration
The API retrieves and processes images directly from DICOMweb-compliant servers, enabling neuropacs™ analysis for streamlined diagnostic workflows.
```java
  // Define DICOMweb parameters
  String wadoUrl = "http://localhost:8080/dcm4chee-arc/aets/DCM4CHEE/rs";
  String studyUid = "1.3.12.2.1107.5.2.32.35162.30000022041820573832300000043";
  String username = "username"; // If not required, use null
  String password = "password"; // If not required, use null

  // Upload a dataset from DICOMweb
  boolean upload = await npcs.uploadDatasetFromDicomWeb(
    orderId,
    wadoUrl,
    studyUid,
    username,  
    password, 
    System.out::println // optional progress callback
  );
```

## Authors

Kerrick Cavanaugh _(Lead Software Engineer)_ - kerrick@neuropacs.com

## Version History

- 1.0.0
  - Initial Release
- 1.0.1
  - DICOMweb intergation
  - Bux fixes
- 1.0.2
  - Added upload optimzations and error handling improvements.
- 1.0.3
  - neuropacs™ Java API latest release.
  - Added retry logic various optimizations.
  - Removed unused dependencies

## License

This project is licensed under the MIT License - see the LICENSE.md file for details
