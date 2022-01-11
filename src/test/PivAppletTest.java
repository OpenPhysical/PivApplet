package test;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;
import javacard.framework.AID;
import net.cooperi.pivapplet.PivApplet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PivAppletTest {
    CardSimulator simulator;
    AID appletAID = AIDUtil.create("A000000308000010000100");

    @BeforeEach
    void setUp() {
        // Re-initialize the simulator for each test
        simulator = new CardSimulator();
    }

    @Test
    void TestInstall() {
        byte[] installParams = new byte[512];
        Arrays.fill(installParams, (byte) 0xFF);
        simulator.installApplet(appletAID, PivApplet.class, installParams, (short) 0, (byte) installParams.length);
    }

    @Test
    void TestSelectResponse() {
        // Install the applet with no parameters
        simulator.installApplet(appletAID, PivApplet.class);

        // The PIX of the AID includes the encoding of the version of the PIV Card Application.
        final byte[] PIV_PIX = {
                (byte)0xa0, (byte)0x00, (byte)0x00, (byte)0x03, (byte)0x08,
                (byte)0x00, (byte)0x00, (byte)0x10, (byte)0x00, (byte)0x01,
                (byte)0x00
        };

        // AID for the PIV applet (without version)
        final byte[] PIV_AID = {
                (byte)0xa0, (byte)0x00, (byte)0x00, (byte)0x03, (byte)0x08
        };

        // See Special Publication 800-73-4
        // 3.1.1 SELECT card command
        // Also see ISO 7816-5 tags at https://emvlab.org/emvtags/all/
        byte[] response = simulator.selectAppletWithResult(appletAID);

        BerTlvParser parser = new BerTlvParser();
        BerTlvs parsed = parser.parse(response);

        // Look for a 0x61 tag (PIV Card Application Property Template)
        BerTlv template = parsed.find(new BerTag(0x61));
        assertNotNull(template, "Unable to find Application Property Template tag.");

        // Find the mandatory elements
        // Full Applet ID (PIX)
        BerTlv PIX = template.find(new BerTag(0x4F));
        assertNotNull(PIX, "PIX is not present in select response.");
        assertArrayEquals(PIV_PIX, PIX.getBytesValue(), "PIX does not match expected.");

        // Coexistent tag allocation authority
        BerTlv authority = template.find(new BerTag(0x79));
        assertNotNull(authority);
        BerTlv AID = authority.find(new BerTag(0x4F));
        assertNotNull(AID, "AID is not present in select response.");
        assertArrayEquals(PIV_AID, AID.getBytesValue(), "AID does not match expected.");

        // Find the optional elements
        // Application Label
        BerTlv applicationLabel = template.find(new BerTag(0x50));
        assertNotNull(applicationLabel, "Application label not present");
        assertTrue(applicationLabel.getTextValue().length() > 0, "Application Label is empty or invalid.");

        // Specification URL
        BerTlv specificationUrl = template.find(new BerTag(0x5F, 0x50));
        assertNotNull(specificationUrl, "Specification URL not present");
        assertTrue(specificationUrl.getTextValue().length() > 0, "Specification URL is empty or invalid.");

        // Supported Algorithms
        List<BerTlv> supportedAlgorithms = template.findAll(new BerTag(0xAC));
        assertTrue(supportedAlgorithms.size() > 0, "Supported algorithms not present.");
    }
}