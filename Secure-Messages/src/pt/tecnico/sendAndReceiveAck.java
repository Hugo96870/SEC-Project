package pt.tecnico;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.*;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.util.Base64;
import java.util.concurrent.Callable;

public class sendAndReceiveAck implements Callable<Integer> {

    //Timeout that defines time between messages
    private static int timeout = 1000;

	private static final int MAX_UDP_DATA_SIZE = (64 * 1024 - 1) - 8 - 20;

	/* Buffer size for receiving a UDP packet. */
	private static final int BUFFER_SIZE = MAX_UDP_DATA_SIZE;

	private static byte[] buf = new byte[BUFFER_SIZE];

    //Create instance of auxFunctions
    private static auxFunctions auxF = new auxFunctions();

    private DatagramPacket packetToSend;
    private Integer portToSend;
    private Integer myPort;

    public sendAndReceiveAck(DatagramPacket packet, Integer port, Integer myPort){
        packetToSend = packet;
        portToSend = port;
        this.myPort = myPort;
    }
    
    @Override
    public Integer call() throws Exception {
        System.out.println("Thread started");

        try{
            DatagramSocket socket = null;
            try{
                if(myPort.equals(0)){ //When communicating between servers 
                    socket = new DatagramSocket();
                }
                else{
                    socket = new DatagramSocket(myPort); //Communications involving client and snapshot
                }
            }catch(Exception e){
                System.err.println("Failed to create socket");
                System.err.println(e.getMessage());
            }

            //Set socket timeout
            socket.setSoTimeout(timeout);

            //Flag to verify if the ack was received or not
            boolean ackReceived = false;

            System.out.printf("Response packet sent to %d!\n", packetToSend.getPort());

            //Send the packet until receive the ack
            while(!ackReceived){
                socket.send(packetToSend);
                try {

                    //Receive ack from message sent
                    DatagramPacket ackDatagram = new DatagramPacket(buf, buf.length);
                    socket.receive(ackDatagram);

                    String clientText = auxF.ConvertReceived(Base64.getEncoder().encodeToString(ackDatagram.getData()), ackDatagram.getLength());

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
                    //Expected ack was not received and increase the timeout to not overflow the network
                    else{
                        timeout += 1000;
                    }
                } catch (SocketTimeoutException e) {
                    //Expected ack was not received and increase the timeout to not overflow the network
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