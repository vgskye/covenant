package link.e4mc.covenant.proof;

import java.util.Arrays;
import java.util.Objects;

public class Cosignature {
    public final byte[] keyHash;
    public final long timestamp;
    public final byte[] signature;

    public Cosignature(byte[] keyHash, long timestamp, byte[] signature) {
        this.keyHash = keyHash;
        this.timestamp = timestamp;
        this.signature = signature;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Cosignature that = (Cosignature) o;
        return timestamp == that.timestamp && Objects.deepEquals(keyHash, that.keyHash) && Objects.deepEquals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(keyHash), timestamp, Arrays.hashCode(signature));
    }

    @Override
    public String toString() {
        return "Cosignature{" +
                "keyHash=" + Arrays.toString(keyHash) +
                ", timestamp=" + timestamp +
                ", signature=" + Arrays.toString(signature) +
                '}';
    }
}
