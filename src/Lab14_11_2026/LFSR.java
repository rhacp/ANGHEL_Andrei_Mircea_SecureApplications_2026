package Lab14_11_2026;

import java.util.Arrays;
import java.util.Objects;

/**
 * Implements a 32-bit Linear Feedback Shift Register (Lab14_11_2026.LFSR).
 * Polynomial: x31 + x7 + x5 + x3 + x2 + x + 1
 */
public class LFSR {

    // store the 32 bits
    // 1. Use an integer, because it has 32 bits
    // 2. byte array byte[4]
    // 3. BitSet

    private byte[] register = new byte[4];

    /**
     * At register level
     *
     * @param index - index to retrieve from register
     * @return byte at index
     */
    private byte getBitAtIndex(int index) {
        int byteIndex = 3 - index / 8;
        int bitIndex = index % 8;

        byte bitByte = this.register[byteIndex];
        byte bitValue = (byte) (bitByte & 0xFF & (1 << bitIndex));
        return (byte) (bitValue != 0 ? 1 : 0);
    }

    //shifts a byte from the register by 1 to the left and returns the most significant bit
    private byte shiftAndReturn(int byteRegisterIndex) {
        byte msb = (byte) (0xFF & (this.register[byteRegisterIndex] & (1 << 7)));
        this.register[byteRegisterIndex] = (byte) (0xFF & (this.register[byteRegisterIndex] << 1));
        return (byte) (msb != 0 ? 1 : 0);
    }

    private void addLSB(int registerIndex, byte lsb) {
        this.register[registerIndex] = (byte) (this.register[registerIndex] | lsb);
    }

    //apply a Lab14_11_2026.LFSR cycle
    public byte cycle() {
        byte temp = (byte) (getBitAtIndex(31) ^
                getBitAtIndex(7) ^
                getBitAtIndex(5) ^
                getBitAtIndex(3) ^
                getBitAtIndex(2) ^
                getBitAtIndex(1) ^
                getBitAtIndex(0));

        byte outputBit1 = shiftAndReturn(3);
        addLSB(3, temp);
        byte outputBit2 = shiftAndReturn(2);
        addLSB(2, outputBit1);
        byte outputBit3 = shiftAndReturn(1);
        addLSB(1, outputBit2);
        byte randomBit = shiftAndReturn(0);
        addLSB(0, outputBit3);

        return randomBit;
    }

    public void init(byte[] seed) {
        for (int i = 0; i < this.register.length; i++) {
            this.register[i] = (byte) seed[i];
        }
    }

    public int getRegisterAsInt() {
        return ((register[0] & 0xFF) << 24)
                | ((register[1] & 0xFF) << 16)
                | ((register[2] & 0xFF) << 8)
                |  (register[3] & 0xFF);
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        LFSR lfsr = (LFSR) o;
        return Objects.deepEquals(register, lfsr.register);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(register);
    }
}
