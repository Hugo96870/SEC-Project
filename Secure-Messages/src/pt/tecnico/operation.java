package pt.tecnico;

public class operation{

    enum operation_type{
        TRANSFER,
        CREATE;
    }

    operation_type identifier;
    byte[] source;
    byte[] destination;
    Integer amount;

    public operation(String identifier, byte[] source, byte[] destination, Integer amount){
        this.identifier = operation_type.TRANSFER;
        this.source = source;
        this.destination = destination;
        this.amount = amount;
    }

    public operation(String identifier, byte[] source){
        this.identifier = operation_type.CREATE;
        this.source = source;
    }

    public byte[] getSource(){
        return source;
    }

    public byte[] getDestination(){
        return destination;
    }

    public Integer getAmount(){
        return amount;
    }

    public operation_type getID(){
        return identifier;
    }

}