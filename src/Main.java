import org.apache.commons.cli.*;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Main {

    public static void main(String[] args) throws IOException {
        // TODO: Get filename from cmd argument AND loop into folder if needed (Create function for it)
        // Get the data depending on the arguments
        byte[] data = parseArguments(args);

        // STEP 1: ICE Decryption
        // 1.1: Create new encryption instance
        IceKey icekey =  new IceKey(2);

        // 1.2: Set the encryption key
        // byte[] key = hexStringToByteArray("4353474F7B3500005E0D000057030000"); // OLD KEY (20190502)
        byte[] key = hexStringToByteArray("4353474F7C3500005F0D000057030000"); // OLD KEY (20190513) --> For test packets
        // byte[] key = hexStringToByteArray("4353474F7E3500005F0D000057030000"); // OLD KEY (20190515)
        // byte[] key = hexStringToByteArray("4353474F7F3500005F0D000057030000"); // OLD KEY (20190517)
        // byte[] key = hexStringToByteArray("4353474F80350000600D000058030000"); // OLD KEY (20190522)
        // byte[] key = hexStringToByteArray("4353474F81350000600D000058030000"); // OLD KEY (20190523)
        //byte[] key = hexStringToByteArray("4353474F82350000600D000058030000"); // OLD KEY (20190530)
        //byte[] key = hexStringToByteArray("4353474F99350000660D000059030000"); // OLD KEY (20191026)

        icekey.set(key);

        // Parse the received packet
        CSGOPacket packet = new CSGOPacket(data,icekey);
        packet.parsePacket();
        packet.printPacket();

        // Fuzz it
        packet.fuzzMSG_PACKETENTITIES();

        // Get new packet
        byte[] newPacket = packet.getRawPacket();

        // Safety check if its changed
        if (Arrays.equals(newPacket,data)){
            System.out.println("Packet didn't change!");
        }else {
            System.out.println("NEW" + bytesToHex(newPacket));
        }

        // Safety check if the packet can still be parsed
        CSGOPacket packet2 = new CSGOPacket(newPacket,icekey);
        try{
            packet2.parsePacket();
            System.out.println("Packet is still valid after being modified");
            //packet2.printPacket();
        }catch (Exception ex){
            System.out.println("ERROR Packet couldn't be converted after being changed..");
        }
    }

    // Parse the arguments here
    private static byte[] parseArguments(String[] args) {
        Options options = new Options();

        Option input = new Option("f", "file", true, "input raw packet with file");
        input.setRequired(false);
        options.addOption(input);

        Option output = new Option("s", "hexstring", true, "input raw packet with hexstring argument");
        output.setRequired(false);
        options.addOption(output);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("CSPLOIT", options);
            System.exit(1);
        }

        // Check if file or hexstring is given:
        if (cmd.hasOption("hexstring")){
            // System.out.println(cmd.getOptionValue("hexstring")); // TODO: Maybe store the orignal received value and check if the content was changed at the end
            String test = cmd.getOptionValue("hexstring");
            return hexStringToByteArray(test);
        } else if (cmd.hasOption("file")){
            try {
                InputStream rawPacket = new FileInputStream(cmd.getOptionValue("file"));
                byte[] packet = rawPacket.readAllBytes();
                //System.out.println(bytesToHex(packet));
                return packet;
            } catch (Exception e) {
                System.out.println("ERROR: Something went wrong when reading the file!");
                e.printStackTrace();
                System.exit(1);
            }
        }else{
            formatter.printHelp("CSPLOIT", options);
            System.exit(1);
        }

        return null;
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
    // To convert hex String to Byte Array (obvious)
    private static byte[] hexStringToByteArray(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(s.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

}
