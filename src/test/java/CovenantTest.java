import link.e4mc.covenant.policy.Group;
import link.e4mc.covenant.policy.Policy;
import link.e4mc.covenant.proof.Proof;
import link.e4mc.covenant.proof.Verifier;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class CovenantTest {
    @Test
    void parsePolicyGeneric20251() throws Exception {
        byte[] policy = CovenantTest.class.getResourceAsStream("sigsum-generic-2025-1").readAllBytes();
        Policy parsed = Policy.parse(policy);
        assertEquals(2, parsed.logs.length);
        assertArrayEquals(Base64.getDecoder().decode("DsfhaEMRmxIDd6c5E6xqy8LQPYJDLiw2uEGwmpWEHyU="), parsed.logs[0].pubkey);
        assertArrayEquals(Base64.getDecoder().decode("8AwVlmPQm72mEx7hgWhjtq3Kz+gLCyiAALEauo/jgxQ="), parsed.logs[1].pubkey);
        assertInstanceOf(Group.class, parsed.quorum);
        Group quorum = (Group) parsed.quorum;
        assertArrayEquals("quorum-rule".getBytes(StandardCharsets.UTF_8), quorum.name);
        assertEquals(2, quorum.k);
        assertEquals(3, quorum.members.length);
        Policy parsedAgain = Policy.parse(policy);
        assertEquals(parsed, parsedAgain);
    }

    @Test
    void parsePolicyTest12025() throws Exception {
        byte[] policy = CovenantTest.class.getResourceAsStream("sigsum-test1-2025").readAllBytes();
        Policy parsed = Policy.parse(policy);
        assertEquals(1, parsed.logs.length);
        assertArrayEquals(Base64.getDecoder().decode("RkSvKr1A9IlaADvKNQ+dWRKrMBpJx38T5bbZBcIKX+Y="), parsed.logs[0].pubkey);
        assertInstanceOf(Group.class, parsed.quorum);
        Group quorum = (Group) parsed.quorum;
        assertArrayEquals("quorum-rule".getBytes(StandardCharsets.UTF_8), quorum.name);
        assertEquals(2, quorum.k);
        assertEquals(3, quorum.members.length);
        Policy parsedAgain = Policy.parse(policy);
        assertEquals(parsed, parsedAgain);
    }

    @Test
    void parsePolicyMadeUp() throws Exception {
        byte[] policy = CovenantTest.class.getResourceAsStream("unit-test-made-up-policy").readAllBytes();
        Policy parsed = Policy.parse(policy);
        assertEquals(3, parsed.logs.length);
        assertInstanceOf(Group.class, parsed.quorum);
        Group quorum = (Group) parsed.quorum;
        assertArrayEquals("test3".getBytes(StandardCharsets.UTF_8), quorum.name);
        assertEquals(4, quorum.k);
        assertEquals(4, quorum.members.length);
        Policy parsedAgain = Policy.parse(policy);
        assertEquals(parsed, parsedAgain);
    }

    @Test
    void parseProof() throws Exception {
        byte[] proof = CovenantTest.class.getResourceAsStream("test.txt.proof").readAllBytes();
        Proof parsed = Proof.parse(proof);
        assertEquals(162993, parsed.size);
        assertEquals(162992, parsed.leafIndex);
        Proof parsedAgain = Proof.parse(proof);
        assertEquals(parsed, parsedAgain);
    }

    @Test
    void parseBadProof() throws Exception {
        byte[] proof = CovenantTest.class.getResourceAsStream("test.txt.proof.bad").readAllBytes();
        assertThrows(IllegalArgumentException.class, () -> {
            Proof.parse(proof);
        });
    }

    @Test
    void verifyProof() throws Exception {
        byte[] file = CovenantTest.class.getResourceAsStream("test.txt").readAllBytes();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(file);
        byte[] pubkey = Base64.getDecoder().decode("61ddsPjMvhQk2bYQM1D5+3RptDW4VZksZV5W4NxP6h8=");
        byte[] message = md.digest();
        byte[] proof = CovenantTest.class.getResourceAsStream("test.txt.proof").readAllBytes();
        Proof proof1 = Proof.parse(proof);
        byte[] policy = CovenantTest.class.getResourceAsStream("sigsum-test1-2025").readAllBytes();
        Policy policy1 = Policy.parse(policy);
        assertTrue(Verifier.verify(policy1, proof1, message, pubkey));
    }

    @Test
    void verifyBadProof() throws Exception {
        byte[] file = CovenantTest.class.getResourceAsStream("unit-test-made-up-policy").readAllBytes();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(file);
        byte[] pubkey = Base64.getDecoder().decode("61ddsPjMvhQk2bYQM1D5+3RptDW4VZksZV5W4NxP6h8=");
        byte[] message = md.digest();
        byte[] proof = CovenantTest.class.getResourceAsStream("test.txt.proof").readAllBytes();
        Proof proof1 = Proof.parse(proof);
        byte[] policy = CovenantTest.class.getResourceAsStream("sigsum-test1-2025").readAllBytes();
        Policy policy1 = Policy.parse(policy);
        assertFalse(Verifier.verify(policy1, proof1, message, pubkey));
    }

    @Test
    void verifyBadProofPolicy() throws Exception {
        byte[] file = CovenantTest.class.getResourceAsStream("test.txt").readAllBytes();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(file);
        byte[] pubkey = Base64.getDecoder().decode("61ddsPjMvhQk2bYQM1D5+3RptDW4VZksZV5W4NxP6h8=");
        byte[] message = md.digest();
        byte[] proof = CovenantTest.class.getResourceAsStream("test.txt.proof").readAllBytes();
        Proof proof1 = Proof.parse(proof);
        byte[] policy = CovenantTest.class.getResourceAsStream("sigsum-generic-2025-1").readAllBytes();
        Policy policy1 = Policy.parse(policy);
        assertFalse(Verifier.verify(policy1, proof1, message, pubkey));
    }

    @Test
    void verifyBadProofInvalid() throws Exception {
        byte[] file = CovenantTest.class.getResourceAsStream("test.txt").readAllBytes();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(file);
        byte[] pubkey = Base64.getDecoder().decode("61ddsPjMvhQk2bYQM1D5+3RptDW4VZksZV5W4NxP6h8=");
        byte[] message = md.digest();
        byte[] proof = CovenantTest.class.getResourceAsStream("test.txt.proof.bad2").readAllBytes();
        Proof proof1 = Proof.parse(proof);
        byte[] policy = CovenantTest.class.getResourceAsStream("sigsum-test1-2025").readAllBytes();
        Policy policy1 = Policy.parse(policy);
        assertFalse(Verifier.verify(policy1, proof1, message, pubkey));
    }
}
