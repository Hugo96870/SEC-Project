package pt.tecnico;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

public class clientWaitResponse implements Callable<Integer> {

    private final static String keyPathPublicServer = "keys/serverPub.der";
	private final static String keyPathPublicServer1 = "keys/serverPub1.der";
	private final static String keyPathPublicServer2 = "keys/serverPub2.der";
	private final static String keyPathPublicServer3 = "keys/serverPub3.der";

	private static final int MAX_UDP_DATA_SIZE = (64 * 1024 - 1) - 8 - 20;

	/* Buffer size for receiving a UDP packet. */
	private final int BUFFER_SIZE = MAX_UDP_DATA_SIZE;

    Integer myPort;

    Integer consensusNumber;

    private static auxFunctions auxF;

    public clientWaitResponse(Integer myPort, auxFunctions auxFunction, Integer consensusNumber){
        auxF = auxFunction;
        this.myPort = myPort;
        this.consensusNumber = consensusNumber;
    }

    public static String parseReceivedMessage(DatagramPacket serverPacket, String path){

		String clientText = null;
		try{
			clientText = auxF.ConvertReceived(Base64.getEncoder().encodeToString(serverPacket.getData()), serverPacket.getLength());
		}catch (Exception e){
			System.err.println("Error parsing");
			System.err.println(e.getMessage());
		}

		//Parse Json with payload and hmac
		JsonObject received = JsonParser.parseString(clientText).getAsJsonObject();
		String receivedFromJson = null, signatureEncrypted = null;
		{
			receivedFromJson = received.get("payload").getAsString();
			signatureEncrypted = received.get("signature").getAsString();
		}

		try{
			String signatureReceived = auxF.do_RSADecryption(signatureEncrypted, path);
			byte[] payloadHash = auxF.digest(receivedFromJson.toString().getBytes(auxF.UTF_8), "SHA3-256");
			String hashString = new String(payloadHash, "UTF-8");
			hashString.equals(signatureReceived);
		}catch (Exception e){
			System.err.println("Error in assymetric decryption");
			System.err.println(e.getMessage());
			System.exit(1);
		}

		// Parse JSON and extract arguments
		JsonObject requestJson = null;
		try{
			requestJson = JsonParser.parseString(receivedFromJson).getAsJsonObject();
		} catch (Exception e){
			System.err.println("Failed to parse Json received");
			System.err.println(e.getMessage());
		}

		// Parse JSON and extract arguments
		String body = null;
		{
			body = requestJson.get("body").getAsString();
		}

		return body;

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
        Map<String, List<Integer>> receivedResponses = new HashMap<String, List<Integer>>();

        DatagramSocket socket = new DatagramSocket(myPort);
		System.out.println("Wait for quorum of responses on port" + myPort);

		//Cycle waitin for quorum
		while(true){
			byte[] serverData = new byte[BUFFER_SIZE];
			DatagramPacket serverPacket = new DatagramPacket(serverData, serverData.length);
			try{
				// Receive response
				socket.receive(serverPacket);

				auxF.sendAck(socket, serverPacket);

				String path = null;
				switch(((Integer)serverPacket.getPort()).toString()){
					case "12000":
						path = keyPathPublicServer;
						break;
					case "12001":
						path = keyPathPublicServer1;
						break;
					case "12002":
						path = keyPathPublicServer2;
						break;
					case "12003":
						path = keyPathPublicServer3;
						break;
				}

				String body = parseReceivedMessage(serverPacket, path);

				// Add to list of received
				if (receivedResponses.get(body) != null){
					if(!receivedResponses.get(body).contains(serverPacket.getPort())){
						receivedResponses.get(body).add(serverPacket.getPort());
					}
				}
				else{
					receivedResponses.put(body, new ArrayList<Integer>());
					receivedResponses.get(body).add(serverPacket.getPort());
				}
				// If we reached consensus
				if(receivedResponses.get(body).size() >= consensusNumber){
                    // Close socket
                    socket.close();
            
                    System.out.printf(body + "\n");
            
                    if(!body.equals("OK")){
                        System.out.println("Vou sair com 1");
                        return 1;
                    }
                    else{
                        System.out.println("Vou sair com 0");
                        return 0;
                    }
				}

			}catch(Exception e){
				System.err.println("Failed in message");
				System.err.println(e.getMessage());
			}
		}
    }
}