import com.google.protobuf.InvalidProtocolBufferException;

import java.io.ByteArrayOutputStream;

public class CSGOProtobuf{
    // Payload variables
    byte cmd;
    byte cmdSize;
    byte[] innerPayload;


public CSGOProtobuf(byte p_cmd,byte p_cmdSize,byte[] p_payload){
    cmd = p_cmd;
    cmdSize = p_cmdSize;
    innerPayload = p_payload;
}

public byte[] getRawProtobuf(){
    try {
        // Assemble the different parts of the packet
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(cmd);

        // Check if payload size changed
        if (innerPayload.length != cmdSize){
            System.out.println("(getRawProtobuf) Payload size got changed from " + innerPayload.length + " bytes to " + cmdSize + " bytes!");
            cmdSize = (byte) innerPayload.length;
        }

        outputStream.write(cmdSize);
        outputStream.write(innerPayload);
        return outputStream.toByteArray();
    }catch (Exception ex){
        System.out.println("(CSGOProtobuf) ERROR: Something went wrong assembling the raw protobuf! (getRawProtobuf)");
        ex.printStackTrace();
        System.exit(1);
    }
    return null;
}

public void parseProtobuf(){ // TODO Fix parseProtobuf and split printInfo
        Integer cmdInt = cmd&0xff;
        Integer cmdSizeInt = cmdSize&0xff;
        // CheckWhichCommand it is
        switch (cmdInt) {
            case Netmessages.NET_Messages.net_Tick_VALUE:
                System.out.println("(PROTOBUFF) Found NET_TICK packet");
                Netmessages.CNETMsg_Tick.Builder msg_tick = Netmessages.CNETMsg_Tick.newBuilder();
                try {
                    msg_tick.mergeFrom(innerPayload);
                    printProtobuf(msg_tick);
                } catch (InvalidProtocolBufferException e) {
                    System.out.println("(PROTOBUFF) Error when converting the packet");
                    e.printStackTrace();
                }
                break;
            case Netmessages.SVC_Messages.svc_PacketEntities_VALUE:
                System.out.println("(PROTOBUFF) Found SVC_PacketEntities packet");
                Netmessages.CSVCMsg_PacketEntities.Builder msgPacketEntities = Netmessages.CSVCMsg_PacketEntities.newBuilder();
                try {
                    msgPacketEntities.mergeFrom(innerPayload);
                    printProtobuf(msgPacketEntities);
                } catch (InvalidProtocolBufferException e) {
                    System.out.println("(PROTOBUFF) Error when converting the packet");
                    e.printStackTrace();
                }
                break;
            default:
                System.out.println("(PROTOBUFF) Unable to find type. This command is not implemented yet.");
                break;
        }
    }


// PROTOBUFS PRINTERS
private void printProtobuf(Netmessages.CNETMsg_Tick.Builder packet){
        System.out.println("-------- CNETMsg_Tick --------");
        System.out.println("CMD: " + cmd);
        System.out.println("CMD Size: " + cmdSize);
        System.out.println("Tick: " + packet.getTick());
        System.out.println("Host computationtime: " + packet.getHostComputationtime());
        System.out.println("Host computationtime std deviation: " + packet.getHostComputationtimeStdDeviation());
        System.out.println("Host framestarttime std deviation: " + packet.getHostFramestarttimeStdDeviation());
        }


private void printProtobuf(Netmessages.CSVCMsg_PacketEntities.Builder packet){
        System.out.println("-------- CSVCMsg_PacketEntities --------");
        System.out.println("Max entries: " + packet.getMaxEntries());
        System.out.println("Updated Entries: " + packet.getUpdatedEntries());
        System.out.println("Is delta?: " + packet.getIsDelta());
        System.out.println("Update baseline?: " + packet.getUpdateBaseline());
        System.out.println("Baseline: " + packet.getBaseline());
        System.out.println("Delta from: " + packet.getDeltaFrom());
        System.out.println("Entity data: " + packet.getEntityData());
        }



    // To convert from Byte array to hex string
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }



}