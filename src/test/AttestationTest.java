package test;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import net.cooperi.pivapplet.PivApplet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.smartcardio.Card;

class AttestationTest {
    CardSimulator simulator = new CardSimulator();
    AID appletAID = AIDUtil.create("A000000308000010000100");

    @BeforeEach
    void setUp() {
        // Re-initialize the simulator for each test
        simulator.reset();
        
        // Install the applet with no parameters and select it
        simulator.installApplet(appletAID, PivApplet.class);
        simulator.selectApplet(appletAID);
    }

    @Test
    void VerifyCertificateImport() {

    }

    @Test
    void VerifyKeyImport() {

    }

    @Test
    void testDecryptWithF9Fails() {

    }

    @Test
    void testKeyAgreementWithF9Fails() {

    }

    @Test
    void testSignWithF9Fails() {

    }

    @Test
    void VerifyMetadataIsCorrect() {

    }
}