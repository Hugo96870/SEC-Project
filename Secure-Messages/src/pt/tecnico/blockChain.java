package pt.tecnico;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;

import javax.xml.transform.Source;

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

    private final Integer startBalance = 100;
    private final Integer blockSize = 5;

    public server_type sT;

    //Number of servers
    private Integer nrPorts;

    private Integer leaderPort;

    private List<Integer> serverPorts;
    //Number of current instance
	private static Integer instanceNumber;
    //Number to achieve consensus
    private Integer consensusMajority;

    Map<Integer, String> consensusRounds;

    Map<byte[], Integer> accounts;

    List<operation> operations;

    public blockChain(){
        nrPorts = 4;

        serverPorts = new ArrayList<Integer>(nrPorts);
        for(int i = 0; i < nrPorts; i++){
            serverPorts.add(8000 + i);
        }

        leaderPort = 8000;
        consensusMajority = (nrPorts + (nrPorts-1)/3)/2 + 1;
        consensusRounds = new HashMap<Integer,String>();
        instanceNumber = 0;
        accounts = new HashMap<byte[], Integer>();
        operations = new ArrayList<operation>();
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

    public void addToRound(Integer round, String value){
        consensusRounds.put(round, value);
    }

    public Integer getInstance(){
        return instanceNumber;
    }

    public void increaseInstance(){
        instanceNumber++;
    }

    public boolean create_account(byte[] key){
        if(!accounts.containsKey(key)){
            accounts.put(key, startBalance);
            return true;
        }
        System.err.println("Account exists");
        return false;
    }

    public Integer check_balance(byte[] key){
        return accounts.get(key);
    }

    //DUVIDA: TAXA DO LIDER
    public boolean transfer(byte[] source, byte[] destination, int amount){
        if(!accounts.containsKey(source) || !accounts.containsKey(destination) || accounts.get(source) < amount){
            System.err.println("Can't perform the transaction");
            return false;
        }
        accounts.replace(source, accounts.get(source), accounts.get(source) - amount);
        accounts.replace(destination, accounts.get(destination), accounts.get(destination) + amount);
        return true;
    }

    //Execute every operation in the block received
    public void executeBlock(List<operation> block){
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
    }
}