package pt.tecnico;

import java.util.List;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Map;

import java.net.DatagramPacket;

import pt.tecnico.operation.operation_type;

import java.util.HashMap;

public class blockChain{

    //Types of servers
	enum server_type{
		NORMAL,
		LEADER,
		B_PC,
        B_PC_T,
        B_PP;
	}

    public server_type sT;

    //Path to miner's public key
    private final static String keyPathPublicMiner = "keys/serverPub.der";

    //Initial account balance
    private final Double startBalance = 100.0;

    private final Integer blockSize = 5;

    //Miner tax from every transaction
    private Double minerTax = 0.05;

    //Number of servers
    private Integer nrPorts;

    private Integer leaderPort;

    private List<Integer> serverPorts;

    //Number of current instance
	private static Integer instanceNumber;

    //Number to achieve consensus
    private Integer consensusMajority;

    //Map with accounts and its balance
    private Map<PublicKey, Double> accounts;

    //Map with operations and its signature
    private Map<operation, DatagramPacket> operations;

    private PublicKey pubMiner;

    //List of every prepared value by round
    private Map<Integer, List<DatagramPacket>> preparesByRound;

    private auxFunctions auxF = new auxFunctions();

    private Integer round;

    public blockChain(){
        nrPorts = 4;

        serverPorts = new ArrayList<Integer>(nrPorts);
        for(int i = 0; i < nrPorts; i++){
            serverPorts.add(8000 + i);
        }

        leaderPort = 8000;
        consensusMajority = (nrPorts + (nrPorts-1)/3)/2 + 1;
        instanceNumber = 0;
        accounts = new HashMap<PublicKey, Double>();
        operations = new HashMap<operation, DatagramPacket>();
        preparesByRound = new HashMap<Integer, List<DatagramPacket>>();

        pubMiner = auxF.getPublicKey(keyPathPublicMiner);

        accounts.put(pubMiner, startBalance);
        round = 0;
    }

    public Integer getRound(){
        return round;
    }

    public Integer getBlockSize(){
        return blockSize;
    }

    public Integer getNrPorts(){
        return nrPorts;
    }

    public Integer getLeaderPort(){
        return leaderPort;
    }

    public List<Integer> getPorts(){
        return serverPorts;
    }

    public Boolean isLeader(Integer port){
        return leaderPort.equals(port);
    }

    public Integer getConsensusMajority(){
        return consensusMajority;
    }

    public Integer getInstance(){
        return instanceNumber;
    }

    public void increaseInstance(){
        instanceNumber++;
    }

    public boolean create_account(PublicKey key){
        if(!accounts.containsKey(key)){
            accounts.put(key, startBalance);
            return true;
        }
        System.err.println("Account exists");
        return false;
    }

    public Double check_balance(PublicKey key){
        return accounts.get(key);
    }

    public boolean transfer(PublicKey source, PublicKey destination, int amount){
        if(!accounts.containsKey(source) || !accounts.containsKey(destination) || accounts.get(source) < amount
                        || source.equals(destination)){
            System.err.println("Can't perform the transaction");
            return false;
        }
        accounts.replace(source, accounts.get(source), accounts.get(source) - amount);

        accounts.replace(destination, accounts.get(destination), accounts.get(destination) + (amount * (1 - minerTax)));
        accounts.replace(pubMiner,
                accounts.get(pubMiner),
                        accounts.get(pubMiner) + amount * minerTax);
        return true;
    }

    //Execute every operation in the block received
    public Map<operation, DatagramPacket> executeBlock(List<operation> block, List<DatagramPacket> signatures){
        int counter = 0;
        for(operation op: block){
            if(op.getID().equals(operation_type.CREATE)){
                if(create_account(op.getSource())){
                    operations.put(op, signatures.get(counter));
                }
            }
            else{
                if(transfer(op.getSource(), op.getDestination(), op.getAmount())){
                    operations.put(op, signatures.get(counter));
                }
            }
            counter++;
        }

        return this.operations;
    }

    public void printState(){
        for(PublicKey key: accounts.keySet()){
            System.out.println("Account: " + key);
            System.out.println("Balance: " + accounts.get(key));
        }
    }

    public List<DatagramPacket> getPreparesByRound(Integer round){
        return preparesByRound.get(round);
    }

    //Add vote to blockChain list of prepared value for some round
    public void addPrepareToRound(Integer round, DatagramPacket packet){
        if(preparesByRound.get(round) == null){
            preparesByRound.put(round, new ArrayList<DatagramPacket>());
            preparesByRound.get(round).add(packet);
        }
        else{
            preparesByRound.get(round).add(packet);
        }
    }

    public Map<PublicKey, Double> getAccounts(){
        return accounts;
    }
}