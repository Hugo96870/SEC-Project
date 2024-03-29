package pt.tecnico;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.*;
import javax.crypto.Cipher;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import com.google.gson.JsonObject;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.io.File;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import com.google.gson.JsonParser;

public class auxFunctions {

    public final Charset UTF_8 = StandardCharsets.UTF_8;

    //Function that verifies digital signature
    public boolean verifySignature(String signatureEncrypted, String pathToKey, String receivedFromJson) throws Exception{

        String signatureReceived = do_RSADecryption(signatureEncrypted, pathToKey);
        byte[] payloadHash = digest(receivedFromJson.toString().getBytes(UTF_8), "SHA3-256");
        String hashString = new String(payloadHash, "UTF-8");
        return hashString.equals(signatureReceived);
    }

    //Encrypt data with private key and RSA
    public String do_RSAEncryption(String plainText, String path) throws Exception
    {

		// Load the private key from the .key file
		byte[] privateKeyBytes = Files.readAllBytes(Paths.get(path));
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        // Convert the string to be encrypted into a byte array
        byte[] plaintextBytes = plainText.getBytes("UTF-8");

        // Create an instance of the Cipher class using the RSA algorithm and initialize it with the private key
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        // Use the Cipher object to encrypt the byte array
        byte[] ciphertextBytes = cipher.doFinal(plaintextBytes);

        // Encode the encrypted byte array into a string using Base64 encoding
        String ciphertext = Base64.getEncoder().encodeToString(ciphertextBytes);

		return ciphertext;
    }

    //Decrypt data with public key and RSA
    public String do_RSADecryption(String cipherText, String path) throws Exception
    {
        // Load the public key from the .key file
        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(path));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        // Decode the encrypted string from Base64 encoding to a byte array
    	byte[] ciphertextBytes = Base64.getDecoder().decode(cipherText);

        // Create an instance of the Cipher class using the RSA algorithm and initialize it with the public key
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        // Use the Cipher object to decrypt the byte array
        byte[] plaintextBytes = cipher.doFinal(ciphertextBytes);

        // Convert the decrypted byte array to a string
        String plaintext = new String(plaintextBytes, "UTF-8");

		return plaintext;
    }

    //Sends ack to host that sent the packet
    public void sendAck(DatagramSocket socket, DatagramPacket packet){
		// Create request message
		JsonObject message = JsonParser.parseString("{}").getAsJsonObject();
		{
			message.addProperty("value", "ack");
		}
		try{
            String clientDataToSend = ConvertToSend(message.toString());

            DatagramPacket ackPacket = new DatagramPacket(Base64.getDecoder().decode(clientDataToSend),
            Base64.getDecoder().decode(clientDataToSend).length, packet.getAddress(), packet.getPort());

            //send ack datagram
            socket.send(ackPacket);
            System.out.println("Sent ack to: " + packet.getPort());

		} catch (Exception e){
			System.err.println("Failed to send ack");
            System.err.println(e.getMessage());
		}
	}

    //Function that converts data to be processed by the program
    public String ConvertToSend(String plainText) throws Exception
    {
		// Convert the string to be encrypted to a byte array
		byte[] plaintextBytes = plainText.getBytes("UTF-8");

		// Encode the encrypted byte array to Base64 encoding
		String clientDataToSend = Base64.getEncoder().encodeToString(plaintextBytes);

		return clientDataToSend;
    }

	//Function that converts data to be sent through a socket
    public String ConvertReceived(String cipherText, int lenght) throws Exception
    {
		byte[] ciphertextBytes = Base64.getDecoder().decode(cipherText);

		byte[] finalCipherText = new byte[lenght];
		System.arraycopy(ciphertextBytes, 0, finalCipherText, 0, lenght);

		// Convert the decrypted byte array to a string
		String clientText = new String(finalCipherText, "UTF-8");

		return clientText;
    }

    //Function that returns hash from a byte sequence
    public byte[] digest(byte[] input, String algorithm) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
        byte[] result = md.digest(input);
        return result;
	}

    //Verify integrity comparing received hmac with Json hmac
    public boolean checkIntegrity(String hmac, JsonObject requestJson){
		byte[] hmacToCheck = null;
		try{
			hmacToCheck = digest(requestJson.toString().getBytes(UTF_8), "SHA3-256");
		}catch (IllegalArgumentException e){
			System.err.println("Failed to hash value");
            System.err.println(e.getMessage());
		}

		if(Base64.getEncoder().encodeToString(hmacToCheck).equals(hmac)){
			return true;
		}
		return false;
	}

    //Get Public key from path
    public PublicKey getPublicKey(String path){
        
        File file = new File(path);
        PublicKey publicKey = null;
        try{
            byte[] keyBytes = Files.readAllBytes(file.toPath());
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            publicKey = kf.generatePublic(spec);
        } catch (Exception e){
            System.err.println("Cant load key");
            System.err.println(e.getMessage());
        }

        return publicKey;
    }

    //Convert String encoded in Base64 into Public Key
    public PublicKey convertStrToPK(String key){

        byte[] keyByte = Base64.getDecoder().decode(key);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyByte);
        PublicKey publicKey = null;
        try{
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(publicKeySpec);
        } catch(Exception e){
            System.err.println("Convertion error");
            System.err.println(e.getMessage());
        }

        return publicKey;
    }

}