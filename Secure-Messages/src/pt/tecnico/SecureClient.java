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
import java.util.Scanner;

public class SecureClient {

	private static final int MAX_UDP_DATA_SIZE = (64 * 1024 - 1) - 8 - 20;

	private static auxFunctions auxF = new auxFunctions();

	/** Buffer size for receiving a UDP packet. */
	private static final int BUFFER_SIZE = MAX_UDP_DATA_SIZE;

	private static final String SPACE = " ";

	private static String myPriv;

	//Key paths
	private final static String keyPathPublicServer = "keys/serverPub.der";
	private final static String keyPathPublicServer1 = "keys/serverPub1.der";
	private final static String keyPathPublicServer2 = "keys/serverPub2.der";
	private final static String keyPathPublicServer3 = "keys/serverPub3.der";
	private final static String keyPathPrivAlice = "keys/userPriv.der";
	private final static String keyPathPubAlice = "keys/userPub.der";
	private final static String keyPathPrivBob = "keys/userBobPriv.der";
	private final static String keyPathPubBob = "keys/userBobPub.der";
	private final static String keyPathPrivCharlie = "keys/userCharliePriv.der";
	private final static String keyPathPubCharlie = "keys/userCharliePub.der";

	private static Map<String, String> keyByUser = new HashMap<String, String>(); 

	public static String createRequestMessage(){

		Scanner scanner = new Scanner(System.in);
		String line = scanner.nextLine().trim();
		String cmd = line.split(SPACE)[0];

		JsonObject requestJson;
		String keySource = null, keyDestination = null;

		switch (cmd) {
			case("CREATE"):
				String path = keyByUser.get(line.split(SPACE)[1]);
				byte[] publicKey = auxF.getPublicKey(path);

				try{
					keySource = new String(publicKey, "UTF-8");
				} catch(Exception e){
					System.err.println("Error converting key");
					System.err.println(e.getMessage());
				}

				requestJson = JsonParser.parseString("{}").getAsJsonObject();
				{
					requestJson.addProperty("type", cmd);
					requestJson.addProperty("pubKey", keySource);
				}
				break;
			case("TRANSFER"):
				String pathS = keyByUser.get(line.split(SPACE)[1]);
				byte[] publicKeyS = auxF.getPublicKey(pathS);
				String pathD = keyByUser.get(line.split(SPACE)[2]);
				byte[] publicKeyD = auxF.getPublicKey(pathD);

				try{
					keySource = new String(publicKeyS, "UTF-8");
					keyDestination = new String(publicKeyD, "UTF-8");
				} catch(Exception e){
					System.err.println("Error converting key");
					System.err.println(e.getMessage());
				}

				requestJson = JsonParser.parseString("{}").getAsJsonObject();
				{
					requestJson.addProperty("type", cmd);
					requestJson.addProperty("source", keySource);
					requestJson.addProperty("dest", keyDestination);
					requestJson.addProperty("amount", line.split(SPACE)[3]);
				}
				break;
			default:
				requestJson = null;
				break;
		}
		// Create request message

		String signature = null;
		try{
			signature = auxF.do_RSAEncryption(auxF.digest(requestJson.toString().getBytes(auxF.UTF_8), "SHA3-256").toString(), myPriv);
		}
		catch (Exception e){
			System.err.printf("RSA encryption failed\n");
			System.err.println(e.getMessage());
		}

		JsonObject message = JsonParser.parseString("{}").getAsJsonObject();
		{
			message.addProperty("payload", requestJson.toString());
			message.addProperty("signature", signature);
		}

		String dataToSend = null;
		try{
			dataToSend = auxF.ConvertToSend(message.toString());
		}
		catch (Exception e){
			System.err.printf("Error parsing message\n");
			System.err.println(e.getMessage());
		}

		scanner.close();

		return dataToSend;
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
		if (args.length < 4) {
			System.err.println("Argument(s) missing!");
			System.err.printf("Usage: java %s host port%n", SecureClient.class.getName());
			System.exit(1);
		}

		final String serverHost = args[0];
		final InetAddress serverAddress = InetAddress.getByName(serverHost);
		final Integer nrServers = Integer.parseInt(args[1]);
		final String id = args[2];
		final Integer port = Integer.parseInt(args[3]);

		switch(id){
			case "Alice":
				myPriv = keyPathPrivAlice;
				break;
			case "Bob":
				myPriv = keyPathPrivBob;
				break;
			case "Charlie":
				myPriv = keyPathPrivCharlie;
				break;
		}

		List<Integer> serverPorts = new ArrayList<Integer>(nrServers);
		Integer consensusNumber = (nrServers-1)/3 + 1;
		for(int i = 0; i < nrServers; i++){
			serverPorts.add(8000 + i);
		}

		//Populate ID and Paths Map
		keyByUser.put("Alice", keyPathPubAlice);
		keyByUser.put("Bob", keyPathPubBob);
		keyByUser.put("Charlie", keyPathPubCharlie);

		// Create socket
		DatagramSocket socket = new DatagramSocket(port);

		String dataToSend = createRequestMessage();

		ExecutorService executorService = Executors.newFixedThreadPool(serverPorts.size());
		List<sendAndReceiveAck> myThreads = new ArrayList<>();
		List<Future<Integer>> future = new ArrayList<>();

		for(int i = 0; i < nrServers; i++){
			//SendMessagetoAll

			DatagramPacket clientPacket = new DatagramPacket(Base64.getDecoder().decode(dataToSend),
					Base64.getDecoder().decode(dataToSend).length, serverAddress, serverPorts.get(i) + 3000);

			myThreads.add(new sendAndReceiveAck(clientPacket, serverPorts.get(i) + 3000, port + 3));
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

		String body = clientWaitForQuorum(consensusNumber, socket);

		// Close socket
		socket.close();

		System.out.printf(body + "\n");

		if(!body.equals("OK")){
			System.out.println("Vou sair com 1");
			System.exit(1);
		}
		else{
			System.out.println("Vou sair com 0");
			System.exit(0);
		}
	}
}