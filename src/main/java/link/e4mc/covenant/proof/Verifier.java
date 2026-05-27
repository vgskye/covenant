package link.e4mc.covenant.proof;

import link.e4mc.covenant.policy.*;
import link.e4mc.covenant.policy.Policy;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class Verifier {
    private static final byte[] TREE_LEAF_WORD = "sigsum.org/v1/tree-leaf\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] TREE_HEAD_WORD = "sigsum.org/v1/tree/".getBytes(StandardCharsets.US_ASCII);

    private static String toHexLowercase(byte[] data) {
        StringBuilder ret = new StringBuilder(data.length * 2);
        for (byte datum : data) {
            ret.append(String.format("%02x", datum));
        }
        return ret.toString();
    }

    private static boolean verifyQuorumWitness(Witness witness, Proof proof) throws SignatureException {
        MessageDigest mdPubkey;
        try {
            mdPubkey = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        mdPubkey.update(witness.pubkey);
        byte[] pubkeyHash = mdPubkey.digest();
        for (Cosignature cosignature : proof.cosignatures) {
            if (Arrays.equals(cosignature.keyHash, pubkeyHash)) {
                EdDSAEngine engine = new EdDSAEngine();
                EdDSAPublicKey key = new EdDSAPublicKey(new EdDSAPublicKeySpec(witness.pubkey, EdDSANamedCurveTable.ED_25519_CURVE_SPEC));
                try {
                    engine.initVerify(key);
                } catch (InvalidKeyException e) {
                    throw new SignatureException(e);
                }
                engine.update(String.format("cosignature/v1\ntime %d\n", cosignature.timestamp).getBytes(StandardCharsets.US_ASCII));
                engine.update(TREE_HEAD_WORD);
                engine.update(toHexLowercase(proof.logKeyHash).getBytes(StandardCharsets.US_ASCII));
                engine.update(String.format("\n%d\n", proof.size).getBytes(StandardCharsets.US_ASCII));
                engine.update(Base64.getEncoder().encode(proof.rootHash));
                engine.update((byte) 0x0A);
                if (!engine.verify(cosignature.signature)) {
                    throw new SignatureException();
                }
                return true;
            }
        }
        return false;
    }

    private static boolean verifyQuorumGroup(Group group, Proof proof) throws SignatureException {
        int verified = 0;
        for (WitnessOrGroup member : group.members) {
            if (verifyQuorum(member, proof)) {
                verified += 1;
            }
            if (verified >= group.k) {
                return true;
            }
        }
        return false;
    }

    private static boolean verifyQuorum(WitnessOrGroup witnessOrGroup, Proof proof) throws SignatureException {
        if (witnessOrGroup instanceof Witness) {
            return verifyQuorumWitness((Witness) witnessOrGroup, proof);
        } else if (witnessOrGroup instanceof Group) {
            return verifyQuorumGroup((Group) witnessOrGroup, proof);
        }
        throw new InvalidParameterException();
    }

    public static boolean verify(Policy policy, Proof proof, byte[] message, byte[] pubkey) {
        try {
            MessageDigest mdPubkey = MessageDigest.getInstance("SHA-256");
            mdPubkey.update(pubkey);
            byte[] pubkeyHash = mdPubkey.digest();
            if (!Arrays.equals(proof.leafKeyHash, pubkeyHash)) {
                return false;
            }

            MessageDigest mdMessage = MessageDigest.getInstance("SHA-256");
            mdMessage.update(message);
            byte[] messageHash = mdMessage.digest();

            EdDSAEngine engine = new EdDSAEngine();
            EdDSAPublicKey messageKey = new EdDSAPublicKey(new EdDSAPublicKeySpec(pubkey, EdDSANamedCurveTable.ED_25519_CURVE_SPEC));
            engine.initVerify(messageKey);
            engine.update(TREE_LEAF_WORD);
            engine.update(messageHash);
            if (!engine.verify(proof.leafSignature)) {
                return false;
            }

            Log proofLog = null;
            for (Log log : policy.logs) {
                MessageDigest mdLogPubkey = MessageDigest.getInstance("SHA-256");
                mdLogPubkey.update(log.pubkey);
                if (Arrays.equals(proof.logKeyHash, mdLogPubkey.digest())) {
                    proofLog = log;
                    break;
                }
            }
            if (proofLog == null) {
                return false;
            }

            engine = new EdDSAEngine();
            EdDSAPublicKey logKey = new EdDSAPublicKey(new EdDSAPublicKeySpec(proofLog.pubkey, EdDSANamedCurveTable.ED_25519_CURVE_SPEC));
            engine.initVerify(logKey);
            engine.update(TREE_HEAD_WORD);
            engine.update(toHexLowercase(proof.logKeyHash).getBytes(StandardCharsets.US_ASCII));
            engine.update(String.format("\n%d\n", proof.size).getBytes(StandardCharsets.US_ASCII));
            engine.update(Base64.getEncoder().encode(proof.rootHash));
            engine.update((byte) 0x0A);
            if (!engine.verify(proof.signature)) {
                return false;
            }

            if (policy.quorum != null) {
                if (!verifyQuorum(policy.quorum, proof)) {
                    return false;
                }
            }

            MessageDigest mdLeafHash = MessageDigest.getInstance("SHA-256");
            mdLeafHash.update((byte) 0x00);
            mdLeafHash.update(messageHash);
            mdLeafHash.update(proof.leafSignature);
            mdLeafHash.update(proof.leafKeyHash);
            byte[] curHash = mdLeafHash.digest();
            long i = proof.leafIndex;
            for (byte[] nodeHash : proof.nodeHashes) {
                MessageDigest mdNodeHash = MessageDigest.getInstance("SHA-256");
                mdNodeHash.update((byte) 0x01);
                if ((i & 1) == 0) {
                    mdNodeHash.update(nodeHash);
                    mdNodeHash.update(curHash);
                } else {
                    mdNodeHash.update(curHash);
                    mdNodeHash.update(nodeHash);
                }
                curHash = mdNodeHash.digest();
            }
            return Arrays.equals(curHash, proof.rootHash);
        } catch (Exception e) {
            return false;
        }
    }
}
