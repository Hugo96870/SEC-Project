package pt.tecnico;

import java.util.List;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Map;
import java.nio.file.Files;
import java.nio.file.Paths;

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

    private final static String keyPathPublicMiner = "keys/serverPub.der";

    private final Double startBalance = 100.0;
    private final Integer blockSize = 5;

    private Double minerTax = 0.05;

    public server_type sT;

    //Number of servers
    private Integer nrPorts;

    private Integer leaderPort;

    private List<Integer> serverPorts;
    //Number of current instance
	private static Integer instanceNumber;
    //Number to achieve consensus
    private Integer consensusMajority;

    Map<PublicKey, Double> accounts;

    List<operation> operations;

    PublicKey pubMiner;

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
        operations = new ArrayList<operation>();
        try{
            byte[] publicKeyBytes = Files.readAllBytes(Paths.get(keyPathPublicMiner));
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            pubMiner = keyFactory.generatePublic(keySpec);
        }catch(Exception e){
            System.err.println("Account miner error");
            System.err.println(e.getMessage());
        }

        accounts.put(pubMiner, startBalance);
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
    public List<operation> executeBlock(List<operation> block){
        for(operation op: block){
            if(op.getID().equals(operation_type.CREATE)){
                if(create_account(op.getSource())){
                    operations.add(op);
                }
            }
            else{
                if(transfer(op.getSource(), op.getDestination(), op.getAmount())){
                    operations.add(op);
                }
            }
        }

        return this.operations;
    }

    public void printState(){
        for(PublicKey key: accounts.keySet()){
            System.out.println("Conta: " + key);
            System.out.println("Saldo: " + accounts.get(key));
        }
    }
}