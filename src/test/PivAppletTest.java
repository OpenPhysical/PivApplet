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
    // JCardSim instance and APDU responses
    CardSimulator simulator;
    ResponseAPDU response;

    // PivApplet AID (for use with the simulator)
    final AID appletAID = AIDUtil.create("A000000308000010000100");

    // Returned upon command success
    final int SW_SUCCESS = 0x9000;

    // Gets the serial number for PivApplet
    final byte INS_GET_SERIAL = (byte)0xF8;
    final CommandAPDU getSerialCommand = new CommandAPDU(0x00, INS_GET_SERIAL, 0x00, 0x00);

    // PIVApplet Tags
    final byte TAG_INSTALL_PARAMS = (byte)0x80;
    final byte TAG_SERIAL_NUMBER = (byte)0xFD;
    final byte LENGTH_SERIAL_NUMBER_TAG = (byte)0x04;

    // How long a serial number is (in bytes)
    final int SERIAL_LENGTH = 0x04;

    final short OFFSET_NONE = 0x00;

    // Serial numbers for testing
    final byte[] EMPTY_SERIAL = new byte[]{(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00};
    final byte[] TEST_SERIAL = new byte[]{(byte)0xFE, (byte)0xDC, (byte)0xBA, (byte)0x98};

    @BeforeEach
    void setUp() {
        // Ensure that random is actually random
        System.setProperty("com.licel.jcardsim.randomdata.secure", "1");
        simulator = new CardSimulator();
    }

    @Test
    void TestInstall() {
        simulator.installApplet(appletAID, PivApplet.class);
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

    @Test
    void TestSerialNumber() {
        // Install the applet once and store the serial number for comparison
        simulator.installApplet(appletAID, PivApplet.class);
        simulator.selectApplet(appletAID);

        response = simulator.transmitCommand(getSerialCommand);
        byte[] firstSerial = response.getData();
        assertEquals(SW_SUCCESS, response.getSW(), "GET_SERIAL instruction does not return SW 9000.");
        assertEquals(SERIAL_LENGTH, response.getData().length, "GET_SERIAL instruction returns incorrect length serial number.");
        assertFalse(Arrays.equals(EMPTY_SERIAL, firstSerial), "GET_SERIAL instruction returns an all-zero serial number.");

        // Install the applet again, and verify the serial number has changed
        simulator.resetRuntime();
        simulator.installApplet(appletAID, PivApplet.class);
        simulator.selectApplet(appletAID);
        response = simulator.transmitCommand(getSerialCommand);
        byte[] secondSerial = response.getData();
        assertEquals(SW_SUCCESS, response.getSW(), "GET_SERIAL instruction does not return SW 9000 on second installation.");
        assertEquals(SERIAL_LENGTH, response.getData().length, "GET_SERIAL instruction returns incorrect length serial number on second installation.");
        assertFalse(Arrays.equals(secondSerial, firstSerial), "GET_SERIAL instruction returns duplicate serial numbers.");

        // Test specifying the serial number as an installation parameter
        byte[] installParams = new byte[] {(byte)0x00, (byte)0x00, LENGTH_SERIAL_NUMBER_TAG + 4, TAG_INSTALL_PARAMS,
                LENGTH_SERIAL_NUMBER_TAG + 2, TAG_SERIAL_NUMBER, LENGTH_SERIAL_NUMBER_TAG, (byte)0xFE, (byte)0xDC,
                (byte)0xBA, (byte)0x98};
        simulator.resetRuntime();
        simulator.installApplet(appletAID, PivApplet.class, installParams, OFFSET_NONE, (byte)installParams.length);
        simulator.selectApplet(appletAID);
        response = simulator.transmitCommand(getSerialCommand);
        byte[] customSerial = response.getData();
        assertArrayEquals(TEST_SERIAL, customSerial, "Applet serial number does not match serial number contained in install parameters.");
    }
}