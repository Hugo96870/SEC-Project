package pt.tecnico;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.file.Files;
import java.util.Base64;
import java.nio.file.Paths;
import java.util.concurrent.Callable;

public class sendAndReceiveAck implements Callable<Integer> {

    private static int timeout = 1000;

	private static final int MAX_UDP_DATA_SIZE = (64 * 1024 - 1) - 8 - 20;

	/** Buffer size for receiving a UDP packet. */
	private static final int BUFFER_SIZE = MAX_UDP_DATA_SIZE;

    private static final String keyPathSecret = "keys/secret.key";

	private static byte[] buf = new byte[BUFFER_SIZE];


    DatagramPacket packetToSend;
    Integer portToSend;

    public sendAndReceiveAck(DatagramPacket packet, Integer port){
        packetToSend = packet;
        portToSend = port;
    }

    public static String do_Decryption(String cipherText, String path, int lenght) throws Exception
    {
        // Load the secret key from the .key file
        byte[] secretKeyBytes = Files.readAllBytes(Paths.get(path));
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyBytes, "AES");

		byte[] ciphertextBytes = Base64.getDecoder().decode(cipherText);

		byte[] finalCipherText = new byte[lenght];
		System.arraycopy(ciphertextBytes, 0, finalCipherText, 0, lenght);

        // Create an instance of the Cipher class using the AES algorithm and initialize it with the secret key
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        // Use the Cipher object to decrypt the byte array
        byte[] plaintextBytes = cipher.doFinal(finalCipherText);

        // Convert the decrypted byte array to a string
        String plaintext = new String(plaintextBytes, "UTF-8");

		return plaintext;
    }

    
    @Override
    public Integer call() throws Exception {
        // Code to be executed in this thread
        System.out.println("Thread started");

        try{
            DatagramSocket socket = new DatagramSocket();
            socket.setSoTimeout(timeout);
            boolean ackReceived = false;
            while(!ackReceived){
                System.out.println("Enviei para este. " + portToSend);
                socket.send(packetToSend);
                try {

                    //Receive ack from message sent
                    DatagramPacket ackDatagram = new DatagramPacket(buf, buf.length);
                    System.out.println("Vou esperar ack deste: " + portToSend);
                    socket.receive(ackDatagram);

                    String clientText = do_Decryption(Base64.getEncoder().encodeToString(ackDatagram.getData()), keyPathSecret, ackDatagram.getLength());

                    // Parse JSON and extract arguments
                    JsonObject requestJson = JsonParser.parseString(clientText).getAsJsonObject();
                    String ack = null;
                    {
                        ack = requestJson.get("value").getAsString();
                    }


                    System.out.println(ack);
                    // If ack is from the expected server
                    if(ackDatagram.getPort() == portToSend && ack.equals("ack")){
                        System.out.println("Recebi ack deste: " + portToSend);
                        ackReceived = true;
                    }
                    else{
                        timeout += 1000;
                    }
                } catch (SocketTimeoutException e) {
                    //expected ack was not received
                    timeout += 1000;
                    
                }
            }
            socket.close();
        }catch (Exception e){
            System.out.printf("Cant send PrePrepare message\n");
        }

        return 1;
    }

}