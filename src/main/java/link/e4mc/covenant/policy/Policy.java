package link.e4mc.covenant.policy;

import link.e4mc.covenant.ParseHelper;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;

public class Policy {
    public final Log[] logs;
    public final WitnessOrGroup quorum;

    public Policy(Log[] logs, WitnessOrGroup quorum) {
        this.logs = logs;
        this.quorum = quorum;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Policy policy = (Policy) o;
        return Objects.deepEquals(logs, policy.logs) && Objects.equals(quorum, policy.quorum);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(logs), quorum);
    }

    @Override
    public String toString() {
        return "Policy{" +
                "logs=" + Arrays.toString(logs) +
                ", quorum=" + quorum +
                '}';
    }

    private static final byte[] WORD_LOG = "log".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] WORD_WITNESS = "witness".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] WORD_GROUP = "group".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] WORD_QUORUM = "quorum".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] WORD_ALL = "all".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] WORD_ANY = "any".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] WORD_NONE = "none".getBytes(StandardCharsets.US_ASCII);

    private static ArrayList<byte[]> tokenizeLine(byte[] line) {
        ArrayList<byte[]> words = new ArrayList<>();
        int wordStart = 0;
        for (int i = 0; i < line.length; i++) {
            if (line[i] == 0x23) { // '#'
                return words;
            } else if (line[i] == 0x20 || line[i] == 0x09) { // ' ' || '\t'
                if (wordStart < i) {
                    words.add(Arrays.copyOfRange(line, wordStart, i));
                }
                wordStart = i + 1;
            }
        }
        if (wordStart < line.length) {
            words.add(Arrays.copyOfRange(line, wordStart, line.length));
        }
        return words;
    }

    public static Policy parse(byte[] file) {
        ArrayList<ArrayList<byte[]>> lines = new ArrayList<>();
        int lineStart = 0;
        for (int i = 0; i < file.length; i++) {
            if (file[i] == 0x0A) { // '\n'
                ArrayList<byte[]> tokenized = tokenizeLine(Arrays.copyOfRange(file, lineStart, i));
                if (tokenized != null && !tokenized.isEmpty())
                    lines.add(tokenized);
                lineStart = i + 1;
            }
        }
        if (lineStart < file.length) {
            ArrayList<byte[]> tokenized = tokenizeLine(Arrays.copyOfRange(file, lineStart, file.length));
            if (tokenized != null && !tokenized.isEmpty())
                lines.add(tokenized);
        }
        ArrayList<Log> logs = new ArrayList<>();
        ArrayList<WitnessOrGroup> elements = new ArrayList<>();
        for (ArrayList<byte[]> line : lines) {
            byte[] term = line.get(0);
            if (Arrays.equals(term, WORD_LOG)) {
                if (line.size() != 2 && line.size() != 3) {
                    throw new IllegalArgumentException();
                }
                byte[] pubkeyHex = line.get(1);
                if (pubkeyHex.length != 64) {
                    throw new IllegalArgumentException();
                }
                logs.add(new Log(ParseHelper.hexDecode(pubkeyHex)));
            } else if (Arrays.equals(term, WORD_WITNESS)) {
                if (line.size() != 3 && line.size() != 4) {
                    throw new IllegalArgumentException();
                }
                byte[] name = line.get(1);
                if (Arrays.equals(name, WORD_NONE)) {
                    throw new IllegalArgumentException();
                }
                byte[] pubkeyHex = line.get(2);
                if (pubkeyHex.length != 64) {
                    throw new IllegalArgumentException();
                }
                byte[] pubkey = ParseHelper.hexDecode(pubkeyHex);
                elements.add(new Witness(name, pubkey));
            } else if (Arrays.equals(term, WORD_GROUP)) {
                if (line.size() < 4) {
                    throw new IllegalArgumentException();
                }
                byte[] name = line.get(1);
                if (Arrays.equals(name, WORD_NONE)) {
                    throw new IllegalArgumentException();
                }
                byte[] kStr = line.get(2);
                int k;
                if (Arrays.equals(kStr, WORD_ANY)) {
                    k = 1;
                } else if (Arrays.equals(kStr, WORD_ALL)) {
                    k = line.size() - 3;
                } else {
                    k = (int) ParseHelper.intDecode(kStr);
                }
                if (k < 1 || k > (line.size() - 3)) {
                    throw new IllegalArgumentException();
                }
                WitnessOrGroup[] members = new WitnessOrGroup[line.size() - 3];
                for (int i = 3; i < line.size(); i++) {
                    byte[] key = line.get(i);
                    for (WitnessOrGroup element : elements) {
                        if (Arrays.equals(element.getName(), key)) {
                            members[i - 3] = element;
                            break;
                        }
                    }
                    if (members[i - 3] == null) {
                        throw new IllegalArgumentException();
                    }
                }
                elements.add(new Group(name, k, members));
            } else if (Arrays.equals(term, WORD_QUORUM)) {
                if (line.size() != 2) {
                    throw new IllegalArgumentException();
                }
                byte[] name = line.get(1);
                if (Arrays.equals(name, WORD_NONE)) {
                    return new Policy(logs.toArray(new Log[0]), null);
                } else {
                    for (WitnessOrGroup element : elements) {
                        if (Arrays.equals(element.getName(), name)) {
                            return new Policy(logs.toArray(new Log[0]), element);
                        }
                    }
                    throw new IllegalArgumentException();
                }
            }
        }
        throw new IllegalArgumentException();
    }
}
