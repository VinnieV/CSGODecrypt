import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;

public class CSGOPacket {

    // Variables
    byte[] decryptedPacket;
    IceKey icekey;
    ByteBuffer packet; // NEW ONE

    // First header variables
    byte firstHeaderSize; // First byte of packet is header length // TODO Convert to int?
    byte[] firstHeaderData;

    // Payload variables
    int payloadSize;
    byte[] payload;

    // Payload LZSS ID and LZSS size
    byte LZSS_ID;
    byte LZSS_size;

    // Payload header
    byte[] sequenceNumber; // TODO Convert to int?
    byte[] sequenceAck; // TODO Convert to int?
    byte flags;
    byte[] checksum;
    byte rel_state; // TODO Convert to int?

    // Protobuf payloads
    List<CSGOProtobuf> protobufs = new ArrayList<CSGOProtobuf>();

    // Constructor
    // byte[] cipher: Is the data containing
    public CSGOPacket(byte[] cipher,IceKey p_icekey){
        icekey = p_icekey;
        decryptedPacket = hexStringToByteArray(iceDecryptPacket(cipher,this.icekey));
        System.out.println(bytesToHex(decryptedPacket));
        //  create a byte buffer and wrap the array
        packet = ByteBuffer.wrap(decryptedPacket);
    }

    public void parsePacket(){
        /*
        https://www.unknowncheats.me/forum/counterstrike-global-offensive/335207-csgo-network-traffic.html
        - DONE Intercept
        - DONE Decrypt (ICE)
        - DONE Skip header (first byte of packet is header length)
        - DONE Read payload (first byte after header is size, next is payload itself)
        - Decompress using LZSS if first byte of payload is NET_HEADER_FLAG_COMPRESSED(-3) (first byte should be LZSS_ID and next is decompressed_size)
        - At this point we got an actual packet. Now read 12-byte header: sequence(4), sequence_ack(4), flags(1), checksum(2), rel_state(1)
        - Now check if you should decrypt/decompress payload (PACKET_FLAG_COMPRESSED(1<<1)/PACKET_FLAG_ENCRYPTED(1<<2))
        - Dont forget to skip/read few bytes if there is PACKET_FLAG_CHOKED(1<<4, skip 1 byte) or PACKET_FLAG_CHALLENGE(1<<5, skip 4 bytes)
        - Now read/skip subchannels data if there is PACKET_FLAG_CHALLENGE. I dont really want to write this here, because this is pain in ass.
        - And if there is any unread data left, you finnaly got your protobuf messages!
        - First VarInt32 is message_id, and another VarInt32 is message_size.
        */
        // Get header
        firstHeaderSize = packet.get(); // First byte of packet is header length
        Integer firstHeaderSizeInt = firstHeaderSize&0xff; // Convert to int
        firstHeaderData = new byte[firstHeaderSizeInt];
        packet.get(firstHeaderData);

        // Get payload
        payloadSize = packet.getInt();
        payload = new byte[payloadSize];
        packet.get(payload);

        // Safety check: Check if there are still bytes left which are not parsed
        if (packet.hasRemaining()) {
            System.out.println("(parsePacket) ERROR packet still got " + packet.remaining() + " remaining bytes which will not be parsed!");
        }

        // Create ByteBuffer from payload
        ByteBuffer payload2 = ByteBuffer.wrap(payload);

        // Get LZSS ID and size
        //LZSS_ID = payload[0];
        //LZSS_size = payload[1];
        // TODO: Didn't figure out what NET_HEADER_FLAG_COMPRESSED(-3) means so no decompression yet... and if these LZSS ID are needed

        // 12-byte header: sequence(4), sequence_ack(4), flags(1), checksum(2), rel_state(1)
        // sequence(4):
        sequenceNumber = new byte[4];
        payload2.get(sequenceNumber,0,4);
        // sequence_ack(4):
        sequenceAck = new byte[4];
        payload2.get(sequenceAck,0,4);
        // flags(1):
        flags = payload2.get();
        // checksum(2):
        checksum = new byte[2];
        payload2.get(checksum,0,2);;
        // rel_state(1):
        rel_state = payload2.get();

        // Check flags to know if I can convert the packet //TODO: Support compression/encryption/channels etc..
        if (flags < 0xE1){ // TODO Really have to fix this one -.-
            System.out.println("Convertable PACKET");
            // Parse the protobufs
            byte[] protobufsRaw = new byte[payloadSize-12];
            payload2.get(protobufsRaw,0,payloadSize-12);
            try {
                parseProtobuff(protobufsRaw);
            }catch (Exception ex){
                System.out.println("(parsePacket) Failed to parse the protobuffs.");
            }
        }else{
            System.out.println("NOT Convertable PACKET");
            return;
        }
    }

    // Parse the protobuff payload data with the CSGOPayload class
    private void parseProtobuff(byte[] data)  {
        byte[] protobufSection;
        CSGOProtobuf newProtobufSection;
        ByteBuffer payload2 = ByteBuffer.wrap(data);

        while (payload2.hasRemaining()){
            byte cmd2 = payload2.get();
            byte cmdSize2 = payload2.get();

            protobufSection = new byte[cmdSize2&0xff];
            payload2.get(protobufSection,0,cmdSize2&0xff);

            // Create new protobuff object with CSGOPayload
            newProtobufSection = new CSGOProtobuf(cmd2,cmdSize2,protobufSection);

            // Store this protobuf in list
            protobufs.add(newProtobufSection);
        }
    }


    // Print packet info
    public void printPacket(){
        System.out.println("Packet size: " + decryptedPacket.length);

        Integer firstHeaderSizeInt = firstHeaderSize&0xff;
        System.out.println("Header size: " + firstHeaderSizeInt.toString());
        System.out.println("Payload size: " + payloadSize);

        // Payload header
        //Integer LZSS_IDInt = LZSS_ID&0xff;
        //Integer LZSS_sizeInt = LZSS_size&0xff;
        //System.out.println("LZSS ID: " + LZSS_IDInt.toString() + " LZSS size: " + LZSS_sizeInt.toString() );

        System.out.println("Payload sequence: " + sequenceNumber); // TODO FIX
        System.out.println("Payload sequence ack: " + sequenceAck); // TODO FIX

        Integer flagsInt = flags&0xff;
        String flagsStr = String.format("%8s", Integer.toBinaryString(flagsInt).replace(' ', '0'));
        System.out.println("Payload flags: " + flagsStr);

        System.out.println("Payload checksum: " + bytesToHex(checksum));

        Integer rel_stateInt = rel_state&0xff;
        System.out.println("Payload rel state: " + rel_stateInt.toString());

        // Print protobufs
        for (CSGOProtobuf section: protobufs) {
            section.parseProtobuf();
        }

    }

    /* Section: Fuzzing methods */
    public void fuzzPayloadLength(){
        //payloadSize = ; // TODO FIX AND IMPROVE THIS
            // SELECT A RANDOM SIZE
            // THEN CREATE A NEW BYTE ARRAY FOR PAYLOAD AND STORE SOME DATA RANDOM CHAR IN THERE
        //String fuzz = "A";
        //payload = hexStringToByteArray(fuzz.repeat(10000));
    }

    public void fuzzMSG_PACKETENTITIES(){ // TODO: This should actually be moved to CSGOProtobuf.java :/
        CSGOProtobuf protofuzz;

        for (CSGOProtobuf section: protobufs) {
            if (section.cmd == Netmessages.SVC_Messages.svc_PacketEntities_VALUE) {
                System.out.println("(fuzzMSG_PACKETENTITIES) I will fuzz some packet entities!");
                Netmessages.CSVCMsg_PacketEntities.Builder msgPacketEntities = Netmessages.CSVCMsg_PacketEntities.newBuilder();
                try {
                    msgPacketEntities.mergeFrom(section.innerPayload);
                    // FUZZ HERE
                    Random rand = new Random();

                    // Obtain a number between [0 - 49].
                    //int randMethod = rand.nextInt(2); // INCREASE THIS WHEN ADDING NEW TECHNIQUES
                    // Fixed method:
                    int randMethod = 1;
                    switch (randMethod){
                        case 0: // FUZZ DeltaFrom
                            msgPacketEntities.setDeltaFrom(1000);
                            break;
                        case 1: // FUZZ entity data
                            // Create fuzz data (I am doing everything in HEXstring as its easier to concat in java)
                            int length = 255; // Must be divisble by 2
                            System.out.println("(fuzzMSG_PACKETENTITIES) Fuzzing packetentities with a payload of length: " + length);
                            String fuzz = "A".repeat(length);

                            // Put this fuzz data in a random location in the entity data
                            String entityData = bytesToHex(msgPacketEntities.getEntityData().toByteArray());
                            Random r = new Random();
                            int randomInt = r.nextInt(entityData.length()/2);
                            System.out.println("(fuzzMSG_PACKETENTITIES) Fuzzing packetentities at insertion point: " + randomInt);
                            String newEntityData = entityData.substring(0,randomInt) + fuzz +  entityData.substring(randomInt);

                            // Overwrite the entity data
                            msgPacketEntities.setEntityData(ByteString.copyFrom(hexStringToByteArray(newEntityData)));
                            break;
                        case 2:
                            System.out.println("(fuzzMSG_PACKETENTITIES) Fuzzing UpdatedEntries to 10000000");
                            //msgPacketEntities.setUpdatedEntries(10000000);
                            break;
                        default:
                            System.out.println("(fuzzMSG_PACKETENTITIES) Invalid random method");
                            break;
                    }

                    // Build the packet
                    Netmessages.CSVCMsg_PacketEntities newPayload = msgPacketEntities.build();

                    // Change protobuff payload
                    section.innerPayload = newPayload.toByteArray();

                    // Set new protobuff size
                    System.out.println("(fuzzMSG_PACKETENTITIES) Inner payload size: " + section.innerPayload.length);
                    section.cmdSize = (byte) section.innerPayload.length;
                } catch (InvalidProtocolBufferException e) {
                    System.out.println("(PROTOBUFF) Error when converting the packet");
                    e.printStackTrace();
                }


            }
        }
    }


    // Return the raw bytes of the current state of the packet
    public byte[] getRawPacket(){
        try {
            // Assemble the different parts of the packet
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            // Write First header
            outputStream.write(firstHeaderSize);
            outputStream.write(firstHeaderData);

            // Recalculate payloadSize //TODO: Improve the calculation later on when other things need to be taken in into account
            int newPayloadSize = 12; // 12 Because to add the size of the header
            for (CSGOProtobuf section: protobufs) {
                newPayloadSize += section.getRawProtobuf().length;
            }

            // Check if payloadsize is changed
            if (newPayloadSize != payloadSize){
                System.out.println("(getRawPacket) Payload size got changed from " + payloadSize + " bytes to " + newPayloadSize + " bytes!");
            }

            // Write payloadsize
            try {
                outputStream.write(intToByte(newPayloadSize));
            }catch (Exception ex){
                System.out.println("(getRawPacket) Failed to convert payload size to one byte!");
            }

            // Write 12 byte header
            outputStream.write(sequenceNumber);
            outputStream.write(sequenceAck);
            outputStream.write(flags);
            outputStream.write(checksum);
            outputStream.write(rel_state);

            // Write protobufs
            for (CSGOProtobuf section: protobufs) {
                outputStream.write(section.getRawProtobuf());
                System.out.println(bytesToHex(section.getRawProtobuf()));
            }

            // createBytestream of new packet
            byte[] rawPacket = outputStream.toByteArray();

            // ICE encrypt
            String hexString = iceEncryptPacket(rawPacket,icekey);

            // Return it
            return hexStringToByteArray(hexString);

        }catch (Exception ex){
            System.out.println("(getRawPacket) ERROR: Something went wrong assembling the modified raw packet!");
            ex.printStackTrace();
            System.exit(1);
        }
        return null;
    }

    // Decrypt large data with ICE encryption
    private String iceDecryptPacket(byte[] cipher, IceKey icekey){
        byte blocks[][];
        String result = "";

        // Divide plaintext into chunks of 8
        blocks = divideArray(cipher,8);

        // convert byte array to a numeric array for encryption
        for(int i=0; i<blocks.length; i++) {
            //System.out.println(bytesToHex(blocks[i]));
            // Decrypt the test data
            byte decrypt[] = new byte[8];
            icekey.decrypt(blocks[i],decrypt);
            //System.out.println(bytesToHex(decrypt));
            result += bytesToHex(decrypt);
        }

        // Return hexString
        return result;
    }


    public long unsignedIntToLong(byte[] b) {
        long l = 0;
        l |= b[0] & 0xFF;
        l <<= 8;
        l |= b[1] & 0xFF;
        l <<= 8;
        l |= b[2] & 0xFF;
        l <<= 8;
        l |= b[3] & 0xFF;
        return l;
    }

    // Encrypt large data with ICE encryption
    private String iceEncryptPacket(byte[] plain, IceKey icekey){
        byte blocks[][];
        String result = "";

        // Divide plaintext into chunks of 8
        blocks = divideArray(plain,8);
        // TODO: Remove trailing zeros from last block?? (Maybe not needed) --> Jep this will be needed...

        // convert byte array to a numeric array for encryption
        for(int i=0; i<blocks.length; i++) {
            //System.out.println(bytesToHex(blocks[i]));
            // Encrypt the test data
            byte encrypt[] = new byte[8];
            icekey.encrypt(blocks[i],encrypt);
            //System.out.println(bytesToHex(encrypt));
            result += bytesToHex(encrypt);
        }

        // Return hexString
        return result;
    }

    // Convert byte long to Byte array
    byte[] longToByteArray(long value) {
        return ByteBuffer.allocate(8).putLong(value).array();
    }

    // Convert byte Byte Array to long
    long byteArrayToLong(byte[] array) {
        return ByteBuffer.wrap(array).getLong();
    }


    // To convert hex String to Byte Array (obvious)
    private byte[] hexStringToByteArray(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(s.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    // To convert from Byte array to hex string
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    private  String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    // To split a big byte array into chunks of n size (our case its needed to split 8 bytes each)
    private  byte[][] divideArray(byte[] source, int chunksize) {
        byte[][] ret = new byte[(int)Math.ceil(source.length / (double)chunksize)][chunksize];
        int start = 0;
        for(int i = 0; i < ret.length; i++) {
            ret[i] = Arrays.copyOfRange(source,start, start + chunksize);
            start += chunksize ;
        }
        return ret;
    }

    private byte[] intToByte(int i)
    {
        byte[] result = new byte[4];

        result[0] = (byte) (i >> 24);
        result[1] = (byte) (i >> 16);
        result[2] = (byte) (i >> 8);
        result[3] = (byte) (i /*>> 0*/);

        return result;
    }

}
