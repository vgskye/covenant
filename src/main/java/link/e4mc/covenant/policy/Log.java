package link.e4mc.covenant.policy;

import java.util.Arrays;
import java.util.Objects;

public class Log {
    public final byte[] pubkey;

    public Log(byte[] pubkey) {
        this.pubkey = pubkey;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Log log = (Log) o;
        return Objects.deepEquals(pubkey, log.pubkey);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(pubkey);
    }

    @Override
    public String toString() {
        return "Log{" +
                "pubkey=" + Arrays.toString(pubkey) +
                '}';
    }
}
