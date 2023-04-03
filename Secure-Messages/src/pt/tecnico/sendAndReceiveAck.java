package pt.tecnico;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.*;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.util.Base64;
import java.util.concurrent.Callable;

public class sendAndReceiveAck implements Callable<Integer> {

    private static int timeout = 1000;

	private static final int MAX_UDP_DATA_SIZE = (64 * 1024 - 1) - 8 - 20;

	/* Buffer size for receiving a UDP packet. */
	private static final int BUFFER_SIZE = MAX_UDP_DATA_SIZE;

	private static byte[] buf = new byte[BUFFER_SIZE];

    DatagramPacket packetToSend;
    Integer portToSend;
    Integer myPort;

    public sendAndReceiveAck(DatagramPacket packet, Integer port, Integer myPort){
        packetToSend = packet;
        portToSend = port;
        this.myPort = myPort;
    }


	/*Decryption function with secret key */
    public static String ConvertReceived(String cipherText, int lenght) throws Exception
    {
		byte[] ciphertextBytes = Base64.getDecoder().decode(cipherText);

		byte[] finalCipherText = new byte[lenght];
		System.arraycopy(ciphertextBytes, 0, finalCipherText, 0, lenght);

		// Convert the decrypted byte array to a string
		String clientText = new String(finalCipherText, "UTF-8");

		return clientText;
    }
    
    @Override
    public Integer call() throws Exception {
        // Code to be executed in this thread
        System.out.println("Thread started");

        try{
            DatagramSocket socket = null;
            if(myPort.equals(0)){
                socket = new DatagramSocket();
            }
            else{
                socket = new DatagramSocket(myPort);
            }
            socket.setSoTimeout(timeout);
            boolean ackReceived = false;
            while(!ackReceived){
                socket.send(packetToSend);
                try {

                    //Receive ack from message sent
                    DatagramPacket ackDatagram = new DatagramPacket(buf, buf.length);
                    socket.receive(ackDatagram);

                    String clientText = ConvertReceived(Base64.getEncoder().encodeToString(ackDatagram.getData()), ackDatagram.getLength());

                    // Parse JSON and extract arguments
                    JsonObject requestJson = JsonParser.parseString(clientText).getAsJsonObject();
                    String ack = null;
                    {
                        ack = requestJson.get("value").getAsString();
                    }

                    // If ack is from the expected server
                    if(ackDatagram.getPort() == portToSend && ack.equals("ack")){
                        System.out.println("Received ack from this server: " + portToSend);
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
            System.err.printf("Couldn't send message to " + packetToSend.getAddress() + ":" + packetToSend.getPort() + "\n");
        }
        return 0;
    }

}