package Lab14_11_2026;

import java.util.Arrays;
import java.util.Base64;

public class TestBitwise {

    static public String getHexString(byte[] value) {
        StringBuilder sb = new StringBuilder();
        for (byte b : value) {
            sb.append(String.format("%02X", b));
            sb.append(" ");
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        // Define one byte key with bit 5 = 1
        byte key = 32;
        byte key2 = (byte) 0b0100000;

        // apparently this is the most correct way for visibility
        // 0000 0001 << 5 = 0010 0000
        byte key3 = 1 << 5;

        System.out.println("Key = " + key);
        System.out.println("Key = " + key2);
        System.out.println("Key = " + key3);

        System.out.println("\n----------------------------------------------------\n");

        // define a 1 byte key with bit 6:2 and 3:1
        byte key4 = 0b01001000;
        byte key5 = 1 << 6 | 1 << 3;

        // defining values in hexa
        byte noun = (byte) 0xA3;

        // byte arrays
        // define a DES key on 8 bytes where byte 3 has all bits 1 and the rest are 0
        byte[] desKey = {0, 0, 0, 0, (byte) 0b11111111, 0, 0, 0};
        byte[] desKey2 = {0, 0, 0, 0, (byte) 0xFF, 0, 0, 0};

        // define an AES key on 128 bits where byte 5: AA and byte 7: 3F
        byte[] aesKey = new byte[16];
        aesKey[15 - 5] = (byte) 0xAA;
        aesKey[15 - 7] = (byte) 0x3F;

        // printing values
        System.out.printf("The 1 byte key is %x", key4);
        System.out.printf("\nThe 1 byte key noun is %x", noun);
        System.out.printf("\nThe 1 byte key noun is %X", noun);

        System.out.println("\n\n----------------------------------------------------\n");

        System.out.println("The AES key is: " + getHexString(aesKey));

        // string conversions from byte representations
        // DON'T DO THIS
        byte[] desKey3 = {0x30, (byte) 0x89, 0x00, 0x01, 0x02, (byte) 0xD3, 0x13, (byte) 0xFF};
        System.out.println("DES key = " + getHexString(desKey3));
        String desPass = new String(desKey3);
        System.out.println("DES Pass: " + desPass);

        // storing binary values as Base64
        String base64Representation = Base64.getEncoder().encodeToString(desKey3);
        System.out.println("DES key Base64 Representation is: " + base64Representation);

        byte[] desKey3Copy = Base64.getDecoder().decode(base64Representation);
        System.out.println("DES key copy: " + getHexString(desKey3Copy));

        System.out.println("\n----------------------------------------------------\n");

        // comparing byte arrays
        byte[] desKey4 = {0x30, (byte) 0x89, 0x00, 0x01, 0x02, (byte) 0xD3, 0x13, (byte) 0xFF};

        if (Arrays.equals(desKey3, desKey4)) {
            System.out.println("DES key copy equal");
        } else {
            System.out.println("DES key copy not equal");
        }

        System.out.println("\n----------------------------------------------------\n");

        // bit level shifting << >> >>>
        byte anotherKey = 0b00110111;
        System.out.println(Integer.toBinaryString(anotherKey));

        var changedkey = (byte) (anotherKey << 1);
        System.out.println(Integer.toBinaryString(changedkey));

        changedkey = (byte) (anotherKey << 2);
        System.out.println(Integer.toBinaryString(changedkey));

        changedkey = (byte) (anotherKey << 2);
        System.out.println(Integer.toBinaryString(0xFF & changedkey));

        // always add 0xFF & because you don't know if you altered the sign bit. Make sure you keep only the last bits.

        System.out.println("\n----------------------------------------------------\n");

        //shift to right
        changedkey = (byte) (anotherKey >> 1);
        System.out.println(Integer.toBinaryString(changedkey));

        changedkey = (byte) (anotherKey >> 4);
        System.out.println(Integer.toBinaryString(changedkey));

        System.out.println("\n----------------------------------------------------\n");

        // Java cares about the bit sign ALWAYS! For ignoring it, use >>>

        anotherKey = (byte) 0b10110111;
        System.out.println(Integer.toBinaryString(0xFF & anotherKey));

        changedkey = (byte) (anotherKey >>> 4);
        System.out.println(Integer.toBinaryString(changedkey));

        changedkey = (byte) ((0xFF & anotherKey) >>> 4);
        System.out.println(Integer.toBinaryString(changedkey));

        System.out.println("\n----------------------------------------------------\n");

        anotherKey = (byte) 0b11111000; // -8

        changedkey = (byte) (anotherKey >>> 4);
        System.out.println(Integer.toBinaryString(changedkey));

        changedkey = (byte) ((0xFF & anotherKey) >>> 4);
        System.out.println(Integer.toBinaryString(changedkey));

        System.out.println("\n----------------------------------------------------\n");

        // how to check a bit value
        byte bitValue = (byte) 0b11110111;
        //check bit 6 value
        byte bitMask = (byte) 0b0100000;
        byte bitResult = (byte) (bitValue & bitMask);
        System.out.println(Integer.toBinaryString(bitResult));
        byte bit6Value = 0;

        if (bitResult == 0) {
            System.out.println("Bit 6 is zero");
        } else {
            System.out.println("Bit 6 is not zero");
            bit6Value = 1;
        }

//        System.out.println((bitResult == 0 ? "Bit 6 is 0" : "Bit 6 is 1"));

        // add the bit value into another byte
        byte outputResult = 0x00;
        // add the previous bit on bit 2
        outputResult = (byte) (outputResult | bit6Value << 2);
        System.out.println(Integer.toBinaryString(outputResult));

        System.out.println("\n----------------------------------------------------\n");

        // alternative get bit 6 value
        bitValue = (byte) 0b11110111;
        bit6Value = (byte) ((((bitValue & 0xFF) << 1) & 0xFF) >>> 7);
        System.out.println(Integer.toBinaryString(bit6Value));

        System.out.println("\n----------------------------------------------------\n");

        // alternative get bit 6 value: This is the winner !!!
        bitValue = (byte) 0b11110111;
        bit6Value = (byte) ((bitValue >>> 6) & 1);
        System.out.println(Integer.toBinaryString(bit6Value));

        System.out.println("\n----------------------------------------------------\n");

        bitValue = (byte) 0b10110111;
        byte rotatedValue = (byte) Integer.rotateLeft(bitValue, 3);
        System.out.println(Integer.toBinaryString(0xFF & rotatedValue));

        System.out.println("\n----------------------------------------------------\n");

        // flip bits; resetting a bit =  make it 0; setting a bit = make it 1;
        bitValue = (byte) 0b10110111;
        System.out.println(Integer.toBinaryString(0xFF & bitValue));
        byte flippedValue = (byte) ~bitValue;
        System.out.println(Integer.toBinaryString(flippedValue));

        System.out.println("\n----------------------------------------------------\n");

        // flip bit 2
        bitValue = (byte) 0b10110111;
        System.out.println(Integer.toBinaryString(0xFF & bitValue));
        flippedValue = (byte) (bitValue ^ (1 << 2));
        System.out.println(Integer.toBinaryString(0xFF & flippedValue));

        System.out.println("\n----------------------------------------------------\n");

        // flip bit 2,3 and 6
        bitValue = (byte) 0b10110111;
        System.out.println(Integer.toBinaryString(0xFF & bitValue));
        flippedValue = (byte) (bitValue ^ (1 << 2 | 1 << 3 | 1 << 6));
        System.out.println(Integer.toBinaryString(0xFF & flippedValue));

        System.out.println("\n----------------------------------------------------\n");

        byte[] seed = {(byte) 0xF0, 0x1A, 0x05, 0x15};
        LFSR lfsr = new LFSR();
        lfsr.init(seed);

        for (int i = 0; i < 32; i++) {
            byte random = lfsr.cycle();
            System.out.println(random);
        }

        byte random = lfsr.cycle();
        System.out.println(random);
        random = lfsr.cycle();
        System.out.println(random);
        random = lfsr.cycle();
        System.out.println(random);
        random = lfsr.cycle();
        System.out.println(random);
        random = lfsr.cycle();
        System.out.println(random);
        random = lfsr.cycle();
        System.out.println(random);
        random = lfsr.cycle();
        System.out.println(random);
        random = lfsr.cycle();
        System.out.println(random);
        random = lfsr.cycle();
        System.out.println(random);
        random = lfsr.cycle();
        System.out.println(random);
        random = lfsr.cycle();
        System.out.println(random);
        random = lfsr.cycle();
        System.out.println(random);
        random = lfsr.cycle();
        System.out.println(random);
        random = lfsr.cycle();
        System.out.println(random);
        random = lfsr.cycle();
        System.out.println(random);

        System.out.println(lfsr.getRegisterAsInt());
    }
}