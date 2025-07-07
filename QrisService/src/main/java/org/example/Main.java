package org.example;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.hivemq.client.mqtt.MqttClient;
import com.hivemq.client.mqtt.MqttClientSslConfig;
import com.hivemq.client.mqtt.mqtt3.Mqtt3AsyncClient;
import okhttp3.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONObject;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.UUID;

import static org.example.AESUtils.decryptAES;
import static org.example.RSAUtil.*;

public class Main {
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private static final char[] HEX = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    private static String amountKSN;
    private static String amountIpek;
    private static String generalIpek;
    private static String generalKsn;
    private static String URL = "https://octopus-decoupling.cashlez.com/"; //TODO: BASE URL
    private static String token;
    private static String sAmountKsnIndex;
    private static String sAmountKsn;
    private static String sAmountEnc;
    private static String sAmountSHA512;
    private static String base64KeyQrisStatic =
            "MIIEpAIBAAKCAQEAwMFI4esz6QUY/ndYSARcX2KTCf704HpxGD6j4Nh9PaqGCS++" +
                    "PirLqNEM0/SQRREze9mPVazh+OjnYdMUhYVPI7qCNN6cVsBYqtVwtcnx5JNBKhLt" +
                    "0erBWiW+kWX7OhK/1ssLagsStosxIljgIBJVC4lqyqihFJb0GdOvlPomfZD01bxL" +
                    "0s7o3RmFkuN6FMsl2VAmWG6Lpco6KgsYKVIw8qrgMLWtzS6086Jkbk2vlxatFBkN" +
                    "3C6pPZidHACuPWTmYQioW9PrKcXcqZn9YB+cCU/bHTxNKwoxVpOq6DqoU6xTn+JP" +
                    "EwymDARA+/jHKhPVSerlgXIx5enLNXr/YwYILQIDAQABAoIBAGnTdH08kbJ0bwV+" +
                    "ZoSbiE+CIjJRvQXlk2P5OCYBFbmefppakPs2qbvUklNoKTESQY7UomIqWaI71JUbu" +
                    "1+XEh0Oj+AQ/AqQ7d1U892KsviIdDVyUQl39pHUuSzArc5zbsmxjmG5FJwODXrLC" +
                    "rnw9qov1ubO8CkKu5fWZcbIFAvJbn/GaCtKthIL5rlZDKRYC6+BpAOq5jrfm5txT" +
                    "yJxJs8uSiRIUl9+TwYuw4tZ/Fi4ety0T5B1it20HAgqTB+tAM/38gAGwForFyVTM" +
                    "MRlDHqIT7Sw26XAv6NZmF4QRwArmwnO18RjnfJlBgNHPMk+EerMz9/3N63ZUFmkW" +
                    "uBNf4ECgYEA7T6Tv64WQggnS1u06m2+i1eedR4ny2//EbMva0ujuVfkJQe9CqhTp" +
                    "8ZarhIFF0vOuOl/1NgTGVPrbUmgxRGsmqw9FZDsi2H5lnTdkrEN7ibFW1xA0CuHo" +
                    "xRSQMs3rf6tUSONZT4y2nK3jd8At/m6w57Okkyo4aInGhG4LP1ReSECgYEAz/5RR" +
                    "8sGaFCx/Sk+1wwjtI6tKd14fdgid+FMDr1kaCJvS1FAl6XM96wY1Z2CRvr4PeV9m" +
                    "AIdX8drKaiJcgLdjYTZj7vAO4m0D2PengNyELL8mwZtM+jq3v9jayBF1CSyNAfZE" +
                    "zeLothEMcqMcH0EzKXj6Az/2CpPiVNBPgMXMY0CgYEA0aNlPZCgfHLl/hIoWKrnI" +
                    "AwpqkYeVgc+Ni7HLSGmqCXBJPOkmWFKosuE36JuuzoyjnVOjw7sOYpNU8Im/Vzzz" +
                    "615QLBSRYwq10enb3Ni4tmBtYxcfVapwXI4iKbKKccM8dDfpeIDX8LU7dlrsiZLY" +
                    "YbX9LEm3lLCCKg1vhOOReECgYEAkvD8w1evoyq/VDc7afntj7XsqFMKuP1k/IRyk" +
                    "0dCFD+fmPpCQ+CiuacftGqeiz7q+e+TlzyHPA9KqhejYqSbmUtt2Jmv6WATkXvg3" +
                    "olYoGuTAoK7y5yVsg2DUz9tlb6HFzMkLOtk/xsCspqCNUZdiab5KAtnBHR/1Gi5A" +
                    "vJ0BFECgYAL9ZsQ/r4uuzzujQceTHx/ZmZkIYYmqCyWrCLjMJurRikpNKczoY5+D" +
                    "vPtraeEbWvxLyFJsDYwUUDkZUQDEVtteOjYyCojWV08OoMeRxpmwkOiJho/WF71k" +
                    "sCzmCHDTk03VXDWluZinkC8KAlOf+zd3RDYCV8tccI+qJ3gKICNQQ==";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        //TODO: 1. Function to handle login process
        doLogin();

        //TODO: 1. Function to connect Message Broker MQTT Cashlez
        connectedToMqtt();

        //TODO: 3. Function to encrypt the transaction amount - "Request Data"
        generateEncAmount(5); //TODO: Adjust the amount based on your needs.

        //TODO: 3.a Function to Generate QR Code
        generateQRCode();
    }

    private static void connectedToMqtt() {
        try {
            InputStream is = Main.class.getClassLoader().getResourceAsStream("m2mqtt_ca_cz_prod.crt");

            if (is == null) {
                System.out.println("File not found");
                return;
            }

            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] data = new byte[1024];
            int nRead;
            while ((nRead = is.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream caInput = new ByteArrayInputStream(buffer.toByteArray());
            X509Certificate caCert = (X509Certificate) cf.generateCertificate(caInput);

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("caCert", caCert);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            HostnameVerifier allHostsValid = (hostname, session) -> true;


            MqttClientSslConfig sslConfig = MqttClientSslConfig.builder()
                    .trustManagerFactory(tmf)
                    .hostnameVerifier(allHostsValid)  // override hostname verifier
                    .build();


            String clientId = "client-" + UUID.randomUUID();
            Mqtt3AsyncClient client = MqttClient.builder()
                    .useMqttVersion3()
                    .identifier(clientId)
                    .serverHost("messagebroker.cashlez.com")
                    .serverPort(18883)
                    .sslConfig(sslConfig)
                    .buildAsync();

            client.connect().whenComplete((connAck, throwable) -> {
                if (throwable != null) {
                    System.out.println("Connection failed: " + throwable.getMessage());
                } else {
                    System.out.println("-----------------------Process Message Broker MQTT---------------------------------");
                    System.out.println("Connected: " + connAck);
                }
            });

            client.subscribeWith()
                    .topicFilter("payment/tyo")  // topic yang mau disubscribe {payment/username}
                    .callback(mqtt3Publish -> {
                        byte[] payload = mqtt3Publish.getPayloadAsBytes();
                        String jsonString = new String(payload);
                        try {
                            JSONObject json = new JSONObject(jsonString);
                            String invoiceNum = json.optString("invoice_num", null);
                            String encPayload = json.optString("enc_payload", null);
                            String encIv = json.optString("enc_iv", null);
                            String encKey = json.optString("enc_key", null);
                            if (invoiceNum != null && !invoiceNum.isEmpty()) { //Specifically for QR Dynamic.
                                System.out.println("Received message QRIS Dynamic: ");
                                System.out.println("Topic : " + mqtt3Publish.getTopic());
                                System.out.println("Payload All Received message QRIS Dynamic: " + new String(mqtt3Publish.getPayloadAsBytes()));
                                checkStatusQR(invoiceNum);
                            } else {  //Specifically for QR Static.
                                String hexKey = decryptByPrivateKey(hexStringToBytes(encKey), base64KeyQrisStatic);
                                String hexIv = decryptByPrivateKey(hexStringToBytes(encIv), base64KeyQrisStatic);
                                byte[] baPayload = decryptAES(hexStringToBytes(hexKey), hexStringToBytes(hexIv), hexStringToBytes(encPayload));
                                String hexPayload = bytesToHex(baPayload);

                                System.out.println("Received message QRIS Static: ");
                                System.out.println("Topic : " + mqtt3Publish.getTopic());
                                System.out.println("Payload All Received message QRIS Static: " + hexToString(hexPayload));

                            }

                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    })
                    .send()
                    .whenComplete((subAck, throwable) -> {
                        if (throwable != null) {
                            System.err.println("Subscribe failed: " + throwable.getMessage());
                        } else {
                            System.out.println("Subscribe success!!!!!");
                        }
                    });

            Thread.sleep(5000); // wait for connection
        } catch (IOException e1) {
            e1.getMessage();
        } catch (Exception e) {
            e.getMessage();
        }

    }

    private static void doLogin() {
        String endPoint = URL + "MmCorePsgsHost/v1/login";

        String username = "tyo";
        long timestamp = getCurrentTimestamp();
        String passwrdMd5 = encryptByMD5("123456");
        String timeStamp = String.valueOf(timestamp);
        String pasHas256 = encryptBySHA256(timeStamp + passwrdMd5);

        OkHttpClient client = new OkHttpClient();
        // Buat JSON body
        Map<String, Object> jsonBody = new HashMap<>();
        jsonBody.put("device_timestamp", timeStamp);
        jsonBody.put("isVisibleUsername", false);
        jsonBody.put("pass_hash", pasHas256);
        jsonBody.put("username", username);

        String json = new Gson().toJson(jsonBody);

        RequestBody requestBody = RequestBody.create(
                json,
                MediaType.parse("application/json")
        );

        Request request = new Request.Builder()
                .url(endPoint)
                .post(requestBody)
                .addHeader("Content-Type", "application/json")
                .build();

        try (Response response = client.newCall(request).execute()) {
            System.out.println("------------------------Data Plain Login Request-------------------------------------");
            System.out.println("Username---------------------: " + username);
            System.out.println("device_timestamp-------------: " + timeStamp);
            System.out.println("pass_hash--------------------: " + pasHas256);
            System.out.println("-------------------------Login Process-----------------------------------------------");
            System.out.println("URL path Login-----------:" + request.url().url().getPath());
            System.out.println("Request body-------------:\n" + json);
            System.out.println("Status code--------------: " + response.code());

            String responseBody = response.body().string();
            System.out.println("Response body------------:\n" + responseBody);

            // Parsing JSON untuk ambil token
            JsonObject jsonObject = JsonParser.parseString(responseBody).getAsJsonObject();
            if ("0000".equals(jsonObject.get("response_code").getAsString())) {
                if (jsonObject.has("token")) {
                    token = jsonObject.get("token").getAsString();
                    System.out.println("✅Token Login------------: " + token);

                    //TODO: 2. Function to generate RSA public and private keys - used for the get_general_device_key service
                    generateRSAPublicPrivateKey();
                } else {
                    System.out.println("⚠️Token not found on response.");
                }
            } else {
                String message = jsonObject.get("message").getAsString();
                System.out.println("❌Login failed: " + message);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void generateRSAPublicPrivateKey() {
        Map<String, Object> keyMap = null;
        try {
            keyMap = RSAUtil.initKey();
            String publicKey = getPublicKey(keyMap).trim(); //TODO The public key is sent in the request body of the get_general_device_key service.
            String privateKey = getPrivateKey(keyMap).trim(); //TODO: Store the private key for decrypting the response data (amountKSN, amountIpek, generalIpek, generalKSN) from the get_general_device_key service.
            long timestamp = getCurrentTimestamp();

            System.out.println("----------------------------RSA PublicKey & PrivateKey-------------------------------");
            System.out.println("Public KEY--------------: " + publicKey.trim());
            System.out.println("PRIVATE KEY-------------: " + privateKey.trim());

            //TODO: URL
            String endPoint = URL + "MmCorePsgsHost/v1/get_general_device_key";

            OkHttpClient client = new OkHttpClient();
            // Buat JSON body generalDeviceKey
            Map<String, Object> jsonBody = new HashMap<>();
            jsonBody.put("device_timestamp", timestamp);
            jsonBody.put("device_id", "P551700121971"); //TODO: Replace with the serial number (SN) of the device you are using.
            jsonBody.put("pub_key", publicKey.trim());


            String json = new Gson().toJson(jsonBody);

            RequestBody requestBody = RequestBody.create(
                    json,
                    MediaType.parse("application/json")
            );

            Request request = new Request.Builder()
                    .url(endPoint)
                    .post(requestBody)
                    .addHeader("Content-Type", "application/json")
                    .addHeader("Authorization", token)
                    .build();

            try (Response response = client.newCall(request).execute()) {
                System.out.println("-------------------------Process get_general_device_key--------------------------");
                System.out.println("URL path generalDeviceKey-----------------:" + request.url().url().getPath());
                System.out.println("Request body------------------------------:\n" + json);
                System.out.println("Status code-------------------------------: " + response.code());

                String responseBody = response.body().string();
                System.out.println("Response body-----------------------------:\n" + responseBody);

                // Parsing JSON
                JsonObject jsonObject = JsonParser.parseString(responseBody).getAsJsonObject();

                // get object "enc_keys"
                JsonObject encKeys = jsonObject.getAsJsonObject("enc_keys");

                if (encKeys != null) {
                    String amountKsn = encKeys.get("amount_ksn").getAsString();
                    String amountIpek = encKeys.get("amount_ipek").getAsString();
                    String generalKsn = encKeys.get("general_ksn").getAsString();
                    String generalIpek = encKeys.get("general_ipek").getAsString();

                    //TODO: 2-a Use the private key to decrypt the data: AmountKSN, AmountIpek, GeneralIpek, and GeneralKSN
                    decryptedDataFromResponseWithPrivateKey(amountKsn, amountIpek, generalIpek, generalKsn, privateKey);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static void decryptedDataFromResponseWithPrivateKey(String amKsn, String amIpek, String gIpek, String gKsn, String privateKey) {
        try {
            amountKSN = decryptByPrivateKey(hexStringToBytes(amKsn), privateKey);
            amountIpek = decryptByPrivateKey(hexStringToBytes(amIpek), privateKey);
            generalIpek = decryptByPrivateKey(hexStringToBytes(gIpek), privateKey);
            generalKsn = decryptByPrivateKey(hexStringToBytes(gKsn), privateKey);

            System.out.println("-----------------------Process Decrypt Data using privateKey-------------------------");
            System.out.println("Amount KSN---------------: " + amountKSN); //TODO: From the decrypted Amount KSN, take the last 20 characters
            System.out.println("Amount IPEK--------------: " + amountIpek); //TODO: From the decrypted Amount IPEK, take the last 32 characters
            System.out.println("General IPEK-------------: " + generalIpek); //TODO: From the decrypted General IPEK, take the last 32 characters
            System.out.println("General KSN--------------: " + generalKsn); //TODO: From the decrypted General KSN, take the last 20 characters

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        }
    }

    private static String generateEncAmount(long amountData) {
        //TODO: 1. Create KSN Index
        sAmountKsnIndex = generateRandomHexString();

        //TODO: 2. For Amount KSN, take the first 15 characters and append the KSN Index
        String amountKsn = amountKSN.substring(0, 15) + sAmountKsnIndex;
        byte[] baAmountKsn = hexStringToBytes(amountKsn);
        sAmountKsn = bytesToHex(baAmountKsn);

        //TODO: 3. Handle Amount IPEK
        byte[] baAmountIpek = hexStringToBytes(amountIpek);

        //TODO: 4. Convert plain amount (Long) to HexString
        String hsBaseAmount = Long.toHexString(amountData);
        if (hsBaseAmount.length() % 2 != 0) {
            hsBaseAmount = "0" + hsBaseAmount;
        }
        int iModulus = (hsBaseAmount.length() / 2) % 8;
        if (iModulus != 0) {
            StringBuilder sb = new StringBuilder(hsBaseAmount);
            for (int i = 0; i < 8 - iModulus; i++) {
                sb.insert(0, "00");
            }
            hsBaseAmount = sb.toString();
        }
        hsBaseAmount = hsBaseAmount.toUpperCase();
        byte[] baBaseAmount = hexStringToBytes(hsBaseAmount);

        //TODO: 5. Process Amount Encryption
        byte[] baEncBaseAmount = DUKPTUtil.encryptAmountWithIPEK(baBaseAmount, baAmountKsn, baAmountIpek);
        sAmountEnc = bytesToHex(baEncBaseAmount).toUpperCase();

        //TODO: 6. Generate SHA-512 hash from the amount
        try {
            sAmountSHA512 = generateSHA512(hsBaseAmount);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        System.out.println("-------------------------------Process Encrypted Amount----------------------------------");
        System.out.println("AMOUNT KSN INDEX--------------------: " + sAmountKsnIndex);
        System.out.println("AMOUNT KSN--------------------------: " + sAmountKsn);
        System.out.println("AMOUNT IPEK-------------------------: " + bytesToHex(baAmountIpek));
        System.out.println("AMOUNT Data Plain-------------------: " + amountData);
        System.out.println("AMOUNT Data Hex---------------------: " + bytesToHex(baBaseAmount));
        System.out.println("AMOUNT Result Encrypted-------------: " + sAmountEnc);
        System.out.println("AMOUNT Result SHA512----------------: " + sAmountSHA512);
        return sAmountEnc;
    }

    private static void generateQRCode() {
        String endPoint = URL + "MmCoreQrpsHost/v1/payment/generate_qr_code";

        OkHttpClient client = new OkHttpClient();
        long timestamp = getCurrentTimestamp();

        //JSON body generate QRCode
        Map<String, Object> jsonBody = new HashMap<>();
        jsonBody.put("amount_ksn_index", sAmountKsnIndex);
        jsonBody.put("base_amount_enc", sAmountEnc);
        jsonBody.put("base_amount_hash", sAmountSHA512);
        jsonBody.put("device_id", "P551700121971"); //TODO: Replace with the serial number (SN) of the device you are using.
        jsonBody.put("qr_pay_app_id", "21");
        jsonBody.put("device_timestamp", String.valueOf(timestamp));
        jsonBody.put("pos_cloud_pointer", "");
        jsonBody.put("pos_request_type", "");
        jsonBody.put("settlement_session_num", "");

        String json = new Gson().toJson(jsonBody);

        RequestBody requestBody = RequestBody.create(
                json,
                MediaType.parse("application/json")
        );

        Request request = new Request.Builder()
                .url(endPoint)
                .post(requestBody)
                .addHeader("Content-Type", "application/json")
                .addHeader("Authorization", token)
                .build();

        try (Response response = client.newCall(request).execute()) {
            System.out.println("-------------------------Process generate_qr_code------------------------------------");
            System.out.println("URL path GenerateQRCode-------:" + request.url().url().getPath());
            System.out.println("Request body------------------:\n" + json);
            System.out.println("Status code-------------------: " + response.code());

            String responseBody = response.body().string();
            System.out.println("Response body-----------------:\n" + responseBody);

            // Parsing JSON
            JsonObject jsonObject = JsonParser.parseString(responseBody).getAsJsonObject();

            //TODO: Retrieve the parameters 'general_ksn_index' and 'hs_qr_string_enc'
            String sGeneralKsnIndex = jsonObject.get("general_ksn_index").getAsString();
            String sqrStringEnc = jsonObject.get("hs_qr_string_enc").getAsString();

            //TODO : 3-b Process the QR Code decryption
            decryptedQRStringFromResponse(sGeneralKsnIndex, sqrStringEnc);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void checkStatusQR(String invoice_number) {
        //TODO: URL
        String endPoint = URL + "MmCoreQrpsHost/v1/payment/status_check";

        long timestamp = getCurrentTimestamp();
        OkHttpClient client = new OkHttpClient();
        // Buat JSON body generalDeviceKey
        Map<String, Object> jsonBody = new HashMap<>();
        jsonBody.put("device_timestamp", String.valueOf(timestamp));
        jsonBody.put("invoice_num", invoice_number.trim());


        String json = new Gson().toJson(jsonBody);

        RequestBody requestBody = RequestBody.create(
                json,
                MediaType.parse("application/json")
        );

        Request request = new Request.Builder()
                .url(endPoint)
                .post(requestBody)
                .addHeader("Content-Type", "application/json")
                .addHeader("Authorization", token)
                .build();

        try (Response response = client.newCall(request).execute()) {
            System.out.println("-------------------------Process QRIS status_check--------------------------");
            System.out.println("URL path QRIS status_check-----------------:" + request.url().url().getPath());
            System.out.println("Request body------------------------------:\n" + json);
            System.out.println("Status code-------------------------------: " + response.code());

            String responseBody = response.body().string();
            System.out.println("Response body-----------------------------:\n" + responseBody);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String decryptedQRStringFromResponse(String generalKsnIndex, String qrString) {

        //TODO: 1. Combine General KSN with General KSN Index
        String sGeneralKsn = generalKsn.substring(0, 15) + generalKsnIndex;
        byte[] generalKsnBa = hexToBytes(sGeneralKsn);

        //TODO: 3. General IPEK
        byte[] generalIpekBa = hexToBytes(generalIpek);
        int qrLength = qrString.length();

        int padding = (8 - ((qrString.length() / 2) % 8)) % 8;
        qrString += "00".repeat(padding);

        byte[] generalBa = hexToBytes(qrString);

        //TODO: 4. Process Decrypt QRIS
        byte[] qrResultBa = DUKPTUtil.decryptDataWithIPEK(generalBa, generalKsnBa, generalIpekBa);
        String sqrResultOutput = bytesToHex(qrResultBa).toUpperCase();
        String qrResulss = hexStringToAsciiString(sqrResultOutput);

        System.out.println("-----------------------Process Decrypt QRIS from service---------------------------------");
        System.out.println("General KSN INDEX-------------------------: " + generalKsnIndex); //TODO: Get from response generate_qr_code service param "general_ksn_index"
        System.out.println("General KSN-------------------------------: " + bytesToHex(generalKsnBa)); //TODO: Final General KSN combined with General KSN Index from the response of the "generate_qr_code" service, parameter "general_ksn_index"
        System.out.println("General IPEK------------------------------: " + bytesToHex(generalIpekBa)); //TODO: General IPEK
        System.out.println("Data QR Ecnrypted-------------------------: " + bytesToHex(generalBa)); //TODO: QRIS Encrypted
        System.out.println("Data QR Ecnrypted length---------------------: " + qrLength); //TODO: Length of QRIS Encrypted
        System.out.println("Result decrypted QRIS Hex String-------------: " + sqrResultOutput); //TODO: Decrypted QRIS result in Hex String format
        System.out.println("Result decrypted QRIS Plain------------------: " + qrResulss.trim()); //TODO: Final result of Decrypted QRIS
        return sqrResultOutput;
    }

    //TODO: Function to generate KSN index (random hex string)
    private static String generateRandomHexString() {
        String hexRandom;
        Random random = new Random();
        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < 5; i++) {
            hexString.append(Integer.toHexString(random.nextInt(16)).toUpperCase());
        }

        hexRandom = hexString.toString();
        return hexRandom;
    }

    public static byte[] hexStringToBytes(String hexString) {
        if (hexString == null || hexString.isEmpty()) {
            return null;
        }

        byte[] buffer = new byte[hexString.length() >> 1];
        int stringLength = hexString.length();
        int byteIndex = 0;

        for (int i = 0; i < stringLength; i++) {
            char ch = hexString.charAt(i);
            if (ch == ' ') {
                continue;
            }

            byte hex = isHexChar(ch);
            if (hex < 0) {
                return null;
            }

            int shift = (byteIndex % 2 == 1) ? 0 : 4;
            buffer[byteIndex >> 1] = (byte) (buffer[byteIndex >> 1] | (hex << shift));
            byteIndex++;
        }

        byteIndex >>= 1; // Divide by 2
        if (byteIndex > 0) {
            if (byteIndex < buffer.length) {
                byte[] newBuffer = new byte[byteIndex];
                System.arraycopy(buffer, 0, newBuffer, 0, byteIndex);
                return newBuffer;
            }
        } else {
            return null;
        }
        return buffer;
    }

    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private static byte isHexChar(char ch) {
        if (ch >= '0' && ch <= '9') {
            return (byte) (ch - '0');
        }
        if (ch >= 'A' && ch <= 'F') {
            return (byte) (ch - 'A' + 10);
        }
        if (ch >= 'a' && ch <= 'f') {
            return (byte) (ch - 'a' + 10);
        }
        return -1; // Invalid hex character
    }

    //TODO: Function to generate SHA-512
    private static String generateSHA512(String data) throws NoSuchAlgorithmException {
        MessageDigest mdSHA512 = MessageDigest.getInstance("SHA-512");
        byte[] baSHA512 = mdSHA512.digest(data.getBytes(StandardCharsets.UTF_8));
        return byteArrayToHexString(baSHA512).toLowerCase();
    }

    private static String byteArrayToHexString(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        int v;

        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX[v >>> 4];
            hexChars[j * 2 + 1] = HEX[v & 0x0F];
        }

        return new String(hexChars);
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static String toHexString(byte[] byteArray) {
        return toHexString(byteArray, 0, byteArray.length, false);
    }

    public static String toHexString(byte[] byteArray, int beginIndex, int endIndex, boolean spaceFlag) {
        if (byteArray == null || byteArray.length == 0 || beginIndex < 0 || endIndex > byteArray.length || beginIndex >= endIndex) {
            return "";
        }

        StringBuilder sbuf = new StringBuilder();

        sbuf.append(toHexChar((byteArray[beginIndex] >> 4) & 0xF));
        sbuf.append(toHexChar(byteArray[beginIndex] & 0xF));

        for (int i = beginIndex + 1; i < endIndex; i++) {
            if (spaceFlag) sbuf.append(" ");
            sbuf.append(toHexChar((byteArray[i] >> 4) & 0xF));
            sbuf.append(toHexChar(byteArray[i] & 0xF));
        }
        return sbuf.toString();
    }

    private static char toHexChar(int nibble) {
        return "0123456789ABCDEF".charAt(nibble & 0xF);
    }

    public static byte[] desEncrypt(byte[] input, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (key.length != 8) {
            throw new InvalidKeyException("@ DESCryptoUtil.desEncrypt(). Parameter <key> must be 8 bytes long, but was " + key.length + ".");
        }

        if (input.length != 8) {
            throw new IllegalBlockSizeException("@ DESCryptoUtil.desEncrypt(). Parameter <input> must be 8 bytes long, but was " + input.length + ".");
        }

        Cipher desCipher = Cipher.getInstance("DES/ECB/NoPadding");
        SecretKey keySpec = new SecretKeySpec(key, "DES");
        desCipher.init(Cipher.ENCRYPT_MODE, keySpec);

        return desCipher.doFinal(input);
    }

    public static String hexStringToAsciiString(String hex) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            String str = hex.substring(i, i + 2);
            int decimal = Integer.parseInt(str, 16);
            output.append((char) decimal);
        }
        return output.toString();
    }

    //TODO: Function to encrypt using MD5
    public static String encryptByMD5(String txt) {
        StringBuffer stringBuffer = new StringBuffer();
        String strKu = null;
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.update(txt.getBytes());
            byte[] byteString = messageDigest.digest();
            strKu = bytesToHex(byteString);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return strKu.toLowerCase();
    }

    //TODO: Function to generate timestamp
    public static long getCurrentTimestamp() {
        return System.currentTimeMillis();
    }

    public static String encryptBySHA256(String txt) {
        StringBuilder stringBuffer = new StringBuilder();
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(txt.getBytes());
            byte[] byteString = messageDigest.digest();
            for (byte tmpStrByte : byteString) {
                String tmpEncTxt = Integer.toString((tmpStrByte & 0xff) + 0x100, 16).substring(1);
                stringBuffer.append(tmpEncTxt);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return stringBuffer.toString();
    }

    public static String hexToString(String hex) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            String str = hex.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }
}