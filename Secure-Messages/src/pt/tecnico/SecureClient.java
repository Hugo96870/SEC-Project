package pt.tecnico;

import java.net.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.*;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import javax.crypto.SecretKey;

public class SecureClient {

	private static final int MAX_UDP_DATA_SIZE = (64 * 1024 - 1) - 8 - 20;

	private static auxFunctions auxF = new auxFunctions();

	/** Buffer size for receiving a UDP packet. */
	private static final int BUFFER_SIZE = MAX_UDP_DATA_SIZE;

	//Key paths
	final static String keyPathPublic = "keys/serverPub.der";
	final static String keyPathPublic1 = "keys/serverPub1.der";
	final static String keyPathPublic2 = "keys/serverPub2.der";
	final static String keyPathPublic3 = "keys/serverPub3.der";
	final static String keyPathPriv = "keys/userPriv.der";
	final static String keyPathSecret = "keys/secret.key";

	public static String clientWaitForQuorum(Integer consensusNumber, DatagramSocket socket){
		Map<String, List<Integer>> receivedResponses = new HashMap<String, List<Integer>>();

		//Cycle waitin for quorum
		while(true){
			byte[] serverData = new byte[BUFFER_SIZE];
			DatagramPacket serverPacket = new DatagramPacket(serverData, serverData.length);
			System.out.printf("Wait for quorum of responses\n");
			try{
				// Receive response
				socket.receive(serverPacket);

				auxF.sendAck(socket, serverPacket);

				String path = null;
				switch(((Integer)serverPacket.getPort()).toString()){
					case "12000":
						path = keyPathPublic;
						break;
					case "12001":
						path = keyPathPublic1;
						break;
					case "12002":
						path = keyPathPublic2;
						break;
					case "12003":
						path = keyPathPublic3;
						break;
				}

				String clientText = null;
				try{
					clientText = auxF.ConvertReceived(Base64.getEncoder().encodeToString(serverPacket.getData()), serverPacket.getLength());
				}catch (Exception e){
					System.err.println("Error parsing");
					System.err.println(e.getMessage());
				}

				//Parse Json with payload and hmac
				JsonObject received = JsonParser.parseString(clientText).getAsJsonObject();
				String receivedFromJson = null, pMS = null;
				{
					receivedFromJson = received.get("payload").getAsString();
					pMS = received.get("PMS").getAsString();
				}

				String pMSDecrypted = null;
				try{
					pMSDecrypted = auxF.do_RSADecryption(pMS, path);
				}catch (Exception e){
					System.err.println("Error in assymetric decryption");
					System.err.println(e.getMessage());
				}

				byte[] secretKeyinByte = auxF.digest(pMSDecrypted.getBytes(auxF.UTF_8), "SHA3-256");
				SecretKey key = new SecretKeySpec(secretKeyinByte, 0, secretKeyinByte.length, "AES");

				try{
					receivedFromJson = auxF.do_Decryption(receivedFromJson, key, 32);
				}catch (Exception e){
					System.err.println("Error in symetric decryption");
					System.err.println(e.getMessage());
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
					return body;
				}

			}catch(Exception e){
				System.err.println("Failed in message");
				System.err.println(e.getMessage());
			}
		}
	}

	public static void main(String[] args) throws IOException {
		// Check arguments
		if (args.length < 3) {
			System.err.println("Argument(s) missing!");
			System.err.printf("Usage: java %s host port%n", SecureClient.class.getName());
			System.exit(1);
		}

		final String serverHost = args[0];
		final InetAddress serverAddress = InetAddress.getByName(serverHost);
		final String sentence = args[1];
		final Integer nrServers = Integer.parseInt(args[2]);

		List<Integer> serverPorts = new ArrayList<Integer>(nrServers);

		for(int i = 0; i < nrServers; i++){
			serverPorts.add(8000 + i);
		}

		// Create socket
		DatagramSocket socket = new DatagramSocket(10000);

        // Create request message
		JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
		{
			String bodyText = sentence;
			requestJson.addProperty("body", bodyText);
		}

		String preMasterSecret = "0";

		byte[] secretKeyinByte = auxF.digest(preMasterSecret.getBytes(auxF.UTF_8), "SHA3-256");
		SecretKey key = new SecretKeySpec(secretKeyinByte, 0, secretKeyinByte.length, "AES");

		String clientData = null;
		try{
			clientData = auxF.do_Encryption(requestJson.toString(), key);
		}
		catch (Exception e){
			System.err.printf("AES encryption failed\n");
			System.err.println(e.getMessage());
		}

		String pMSEncrypted = null;
		try{
			pMSEncrypted = auxF.do_RSAEncryption(preMasterSecret, keyPathPriv);
		}
		catch (Exception e){
			System.err.printf("RSA encryption failed\n");
			System.err.println(e.getMessage());
		}

		JsonObject message = JsonParser.parseString("{}").getAsJsonObject();
		{
			message.addProperty("payload", clientData);
			message.addProperty("PMS", pMSEncrypted);
		}

		String dataToSend = null;
		try{
			dataToSend = auxF.ConvertToSend(message.toString());
		}
		catch (Exception e){
			System.err.printf("Error parsing message\n");
			System.err.println(e.getMessage());
		}

		ExecutorService executorService = Executors.newFixedThreadPool(serverPorts.size());
		List<sendAndReceiveAck> myThreads = new ArrayList<>();
		List<Future<Integer>> future = new ArrayList<>();

		for(int i = 0; i < nrServers; i++){
			//SendMessagetoAll

			DatagramPacket clientPacket = new DatagramPacket(Base64.getDecoder().decode(dataToSend),
					Base64.getDecoder().decode(dataToSend).length, serverAddress, serverPorts.get(i) + 3000);

			myThreads.add(new sendAndReceiveAck(clientPacket, serverPorts.get(i) + 3000, 0));
		}

		try{
			for(int i = 0; i < serverPorts.size(); i++){
				future.add(executorService.submit(myThreads.get(i)));
				future.get(i).get();
			}
		}catch(Exception e){
			System.err.println("Error launching threads");
			System.err.println(e.getMessage());
		}

		Integer consensusNumber = (nrServers + (nrServers-1)/3)/2 + 1;

		String body = clientWaitForQuorum(consensusNumber, socket);

		// Close socket
		socket.close();

		System.out.printf(body);

		String finalValue = body.substring(0, body.length() - 1);

		if(!sentence.equals(finalValue)){
			System.out.println("Vou sair com 1");
			System.exit(1);
		}
		else{
			System.out.println("Vou sair com 0");
			System.exit(0);
		}
	}
}