package link.e4mc.covenant;

public class ParseHelper {
    private static byte hexDecodeDigit(byte input) {
        if (0x30 <= input && input <= 0x39) { // 0..9
            return (byte) (input - 0x30);
        } else if (0x41 <= input && input <= 0x46) {
            return (byte) (input - 55);
        } else if (0x61 <= input && input <= 0x66) {
            return (byte) (input - 87);
        }
        throw new IllegalArgumentException();
    }

    public static byte[] hexDecode(byte[] input) {
        byte[] output = new byte[input.length / 2];
        for (int i = 0; i < output.length; i++) {
            byte highDigit = input[i * 2];
            byte lowDigit = input[(i * 2) + 1];
            output[i] = (byte) ((hexDecodeDigit(highDigit) << 4) | hexDecodeDigit(lowDigit));
        }
        return output;
    }

    public static long intDecode(byte[] input) {
        if (input.length == 1) {
            if (0x30 <= input[0] && input[0] <= 0x39) { // 0..9
                return (input[0] - 0x30);
            } else {
                throw new IllegalArgumentException();
            }
        }
        long output = 0;
        for (byte b : input) {
            if (0x30 <= b && b <= 0x39) { // 0..9
                if (output == 0 && b == 0x30) {
                    throw new IllegalArgumentException();
                }
                output = (output * 10) + (b - 0x30);
            } else {
                throw new IllegalArgumentException();
            }
        }
        return output;
    }
}
