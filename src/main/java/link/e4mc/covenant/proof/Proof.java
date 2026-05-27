package link.e4mc.covenant.proof;

import link.e4mc.covenant.ParseHelper;
import link.e4mc.covenant.policy.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;

public class Proof {
    public final byte[] logKeyHash;
    public final byte[] leafKeyHash;
    public final byte[] leafSignature;

    public final long size;
    public final byte[] rootHash;
    public final byte[] signature;
    public final Cosignature[] cosignatures;

    public final long leafIndex;
    public final byte[][] nodeHashes;

    public Proof(byte[] logKeyHash, byte[] leafKeyHash, byte[] leafSignature, long size, byte[] rootHash, byte[] signature, Cosignature[] cosignatures, long leafIndex, byte[][] nodeHashes) {
        this.logKeyHash = logKeyHash;
        this.leafKeyHash = leafKeyHash;
        this.leafSignature = leafSignature;
        this.size = size;
        this.rootHash = rootHash;
        this.signature = signature;
        this.cosignatures = cosignatures;
        this.leafIndex = leafIndex;
        this.nodeHashes = nodeHashes;
    }

    private static final byte[] PHRASE_HEADER = "version=2\nlog=".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PHRASE_LEAF = "\nleaf=".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PHRASE_SIZE = "\n\nsize=".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PHRASE_ROOT_HASH = "\nroot_hash=".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PHRASE_SIGNATURE = "\nsignature=".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PHRASE_COSIGNATURE = "\ncosignature=".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PHRASE_LEAF_INDEX = "\n\nleaf_index=".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PHRASE_NODE_HASH = "\nnode_hash=".getBytes(StandardCharsets.US_ASCII);

    public static Proof parse(byte[] file) {
        int cursor = 0;
        if (!Arrays.equals(PHRASE_HEADER, Arrays.copyOfRange(file, 0, PHRASE_HEADER.length))) {
            throw new IllegalArgumentException();
        }
        cursor += PHRASE_HEADER.length;
        byte[] logKeyHash = ParseHelper.hexDecode(Arrays.copyOfRange(file, cursor, cursor + 64));
        cursor += 64;
        if (!Arrays.equals(PHRASE_LEAF, Arrays.copyOfRange(file, cursor, cursor + PHRASE_LEAF.length))) {
            throw new IllegalArgumentException();
        }
        cursor += PHRASE_LEAF.length;
        byte[] leafKeyHash = ParseHelper.hexDecode(Arrays.copyOfRange(file, cursor, cursor + 64));
        cursor += 64;
        if (file[cursor] != 0x20) {
            throw new IllegalArgumentException();
        }
        cursor++;
        byte[] leafSignature = ParseHelper.hexDecode(Arrays.copyOfRange(file, cursor, cursor + 128));
        cursor += 128;
        if (!Arrays.equals(PHRASE_SIZE, Arrays.copyOfRange(file, cursor, cursor + PHRASE_SIZE.length))) {
            throw new IllegalArgumentException();
        }
        cursor += PHRASE_SIZE.length;
        int nextCursor = cursor;
        while (file[nextCursor] != 0x0A) {
            nextCursor++;
        }
        long size = ParseHelper.intDecode(Arrays.copyOfRange(file, cursor, nextCursor));
        cursor = nextCursor;
        if (!Arrays.equals(PHRASE_ROOT_HASH, Arrays.copyOfRange(file, cursor, cursor + PHRASE_ROOT_HASH.length))) {
            throw new IllegalArgumentException();
        }
        cursor += PHRASE_ROOT_HASH.length;
        byte[] rootHash = ParseHelper.hexDecode(Arrays.copyOfRange(file, cursor, cursor + 64));
        cursor += 64;
        if (!Arrays.equals(PHRASE_SIGNATURE, Arrays.copyOfRange(file, cursor, cursor + PHRASE_SIGNATURE.length))) {
            throw new IllegalArgumentException();
        }
        cursor += PHRASE_SIGNATURE.length;
        byte[] signature = ParseHelper.hexDecode(Arrays.copyOfRange(file, cursor, cursor + 128));
        cursor += 128;
        ArrayList<Cosignature> cosignatures = new ArrayList<>();
        while (file[cursor + 1] != 0x0A) {
            if (!Arrays.equals(PHRASE_COSIGNATURE, Arrays.copyOfRange(file, cursor, cursor + PHRASE_COSIGNATURE.length))) {
                throw new IllegalArgumentException();
            }
            cursor += PHRASE_COSIGNATURE.length;
            byte[] cosignatureKeyHash = ParseHelper.hexDecode(Arrays.copyOfRange(file, cursor, cursor + 64));
            cursor += 64;
            if (file[cursor] != 0x20) {
                throw new IllegalArgumentException();
            }
            cursor++;
            int nextCursorCosig = cursor;
            while (file[nextCursorCosig] != 0x20) {
                nextCursorCosig++;
            }
            long cosignatureTimestamp = ParseHelper.intDecode(Arrays.copyOfRange(file, cursor, nextCursorCosig));
            cursor = nextCursorCosig;
            if (file[cursor] != 0x20) {
                throw new IllegalArgumentException();
            }
            cursor++;
            byte[] cosignature = ParseHelper.hexDecode(Arrays.copyOfRange(file, cursor, cursor + 128));
            cursor += 128;
            cosignatures.add(new Cosignature(cosignatureKeyHash, cosignatureTimestamp, cosignature));
        }
        if (!Arrays.equals(PHRASE_LEAF_INDEX, Arrays.copyOfRange(file, cursor, cursor + PHRASE_LEAF_INDEX.length))) {
            throw new IllegalArgumentException();
        }
        cursor += PHRASE_LEAF_INDEX.length;
        int nextCursorLeafIndex = cursor;
        while (file[nextCursorLeafIndex] != 0x0A) {
            nextCursorLeafIndex++;
        }
        long leafIndex = ParseHelper.intDecode(Arrays.copyOfRange(file, cursor, nextCursorLeafIndex));
        cursor = nextCursorLeafIndex;
        ArrayList<byte[]> nodeHashes = new ArrayList<>();
        while (cursor + 1 < file.length) {
            if (!Arrays.equals(PHRASE_NODE_HASH, Arrays.copyOfRange(file, cursor, cursor + PHRASE_NODE_HASH.length))) {
                throw new IllegalArgumentException();
            }
            cursor += PHRASE_NODE_HASH.length;
            byte[] nodeHash = ParseHelper.hexDecode(Arrays.copyOfRange(file, cursor, cursor + 64));
            cursor += 64;
            nodeHashes.add(nodeHash);
        }
        if (file[cursor] != 0x0A) {
            throw new IllegalArgumentException();
        }
        return new Proof(logKeyHash, leafKeyHash, leafSignature, size, rootHash, signature, cosignatures.toArray(new Cosignature[0]), leafIndex, nodeHashes.toArray(new byte[0][0]));
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Proof proof = (Proof) o;
        return size == proof.size && leafIndex == proof.leafIndex && Objects.deepEquals(logKeyHash, proof.logKeyHash) && Objects.deepEquals(leafKeyHash, proof.leafKeyHash) && Objects.deepEquals(leafSignature, proof.leafSignature) && Objects.deepEquals(rootHash, proof.rootHash) && Objects.deepEquals(signature, proof.signature) && Objects.deepEquals(cosignatures, proof.cosignatures) && Objects.deepEquals(nodeHashes, proof.nodeHashes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(logKeyHash), Arrays.hashCode(leafKeyHash), Arrays.hashCode(leafSignature), size, Arrays.hashCode(rootHash), Arrays.hashCode(signature), Arrays.hashCode(cosignatures), leafIndex, Arrays.deepHashCode(nodeHashes));
    }

    @Override
    public String toString() {
        return "Proof{" +
                "logKeyHash=" + Arrays.toString(logKeyHash) +
                ", leafKeyHash=" + Arrays.toString(leafKeyHash) +
                ", leafSignature=" + Arrays.toString(leafSignature) +
                ", size=" + size +
                ", rootHash=" + Arrays.toString(rootHash) +
                ", signature=" + Arrays.toString(signature) +
                ", cosignatures=" + Arrays.toString(cosignatures) +
                ", leafIndex=" + leafIndex +
                ", nodeHashes=" + Arrays.toString(nodeHashes) +
                '}';
    }
}
