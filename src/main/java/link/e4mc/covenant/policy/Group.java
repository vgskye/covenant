package link.e4mc.covenant.policy;

import java.util.Arrays;
import java.util.Objects;

public class Group implements WitnessOrGroup {
    public final byte[] name;
    public final int k;
    public final WitnessOrGroup[] members;

    public Group(byte[] name, int k, WitnessOrGroup[] members) {
        this.name = name;
        this.k = k;
        this.members = members;
    }

    @Override
    public byte[] getName() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Group group = (Group) o;
        return k == group.k && Objects.deepEquals(name, group.name) && Objects.deepEquals(members, group.members);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(name), k, Arrays.hashCode(members));
    }

    @Override
    public String toString() {
        return "Group{" +
                "name=" + Arrays.toString(name) +
                ", k=" + k +
                ", members=" + Arrays.toString(members) +
                '}';
    }
}
