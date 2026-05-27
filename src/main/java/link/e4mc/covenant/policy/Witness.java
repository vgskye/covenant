package link.e4mc.covenant.policy;

import java.util.Arrays;
import java.util.Objects;

public class Witness implements WitnessOrGroup {
    public final byte[] name;
    public final byte[] pubkey;

    public Witness(byte[] name, byte[] pubkey) {
        this.name = name;
        this.pubkey = pubkey;
    }

    @Override
    public byte[] getName() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Witness witness = (Witness) o;
        return Objects.deepEquals(name, witness.name) && Objects.deepEquals(pubkey, witness.pubkey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(name), Arrays.hashCode(pubkey));
    }

    @Override
    public String toString() {
        return "Witness{" +
                "name=" + Arrays.toString(name) +
                ", pubkey=" + Arrays.toString(pubkey) +
                '}';
    }
}
