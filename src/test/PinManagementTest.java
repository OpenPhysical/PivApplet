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

import static org.junit.jupiter.api.Assertions.*;

public class PinManagementTest {
    CardSimulator simulator;
    AID appletAID = AIDUtil.create("A000000308000010000100");
    ResponseAPDU response;

    // For TLV parsing
    BerTlvParser parser = new BerTlvParser();
    BerTlvs parsed;

    // Yubikey extension to get metadata for a slot
    final byte INS_GET_METADATA = (byte) 0xF7;

    // Standard PIV verify command
    final byte INS_VERIFY = (byte)0x20; // Verifies PIN
    final byte INS_RESET_RETRY = (byte)0x2C; // Resets PIN retries
    final byte INS_CHANGE_REFERENCE_DATA = (byte)0x24;  // Sets PIN/PUK

    // Which slot stores the PIN
    final byte SLOT_PIN = (byte) 0x80;
    final byte SLOT_PUK = (byte) 0x81;

    // Metadata tags
    final BerTag TAG_DEFAULT_VALUE = new BerTag(0x05);
    final BerTag TAG_RETRIES = new BerTag(0x06);

    // Return status codes
    final byte SW1_INCORRECT_PIN = 0x63;
    final int SW_SUCCESS = 0x9000;
    final int SW_NO_TRIES_REMAINING = 0x63C0;

    final byte APPLET_PIN_PADDING = (byte)0xFF;

    final byte[] DEFAULT_PIN = new byte[] {'1', '2', '3', '4', '5', '6', APPLET_PIN_PADDING, APPLET_PIN_PADDING};
    final byte[] DEFAULT_PUK = new byte[] {'1', '2', '3', '4', '5', '6', '7', '8'};

    // PIN and PUK to test changes with
    final byte[] TEST_PIN = new byte[] {'8', '7', '6', '5', '4', '3', '2', '1'};
    final byte[] TEST_PUK = new byte[] {'8', '7', '6', '5', '4', '3', '2', '1'};

    // Invalid zero-length PIN with padding
    final byte[] BAD_PIN = new byte[] {(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF};

    // Current PUK and new PIN
    final byte[] RESET_PUK_GOOD = new byte[] {'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', APPLET_PIN_PADDING, APPLET_PIN_PADDING};
    final byte[] RESET_PUK_BAD = new byte[] {'0', '0', '0', '0', '0', '0', '0', '0', '1', '2', '3', '4', '5', '6', APPLET_PIN_PADDING, APPLET_PIN_PADDING};

    @BeforeEach
    void setUp() {
        // Re-initialize the simulator for each test
        simulator = new CardSimulator();

        // Install and select applet with no parameters
        simulator.installApplet(appletAID, PivApplet.class);
        simulator.selectApplet(appletAID);
    }

    @Test
    void TestVerifyAndSetPIN() throws IOException {
        // Ensure the PIN metadata shows the PIN is default
        final CommandAPDU getPINMetadataCommand = new CommandAPDU(0x00, INS_GET_METADATA, 0x00, SLOT_PIN);
        response = simulator.transmitCommand(getPINMetadataCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "Unable to get metadata for PIN.");
        parsed = parser.parse(response.getData());
        BerTlv isDefaultTag = parsed.find(TAG_DEFAULT_VALUE);
        assertNotNull(isDefaultTag, "Default status not present in PIN metadata.");
        assertEquals(0x01, isDefaultTag.getIntValue(), "Default PIN is not reported as default.");


        // Verify the default PIN
        final CommandAPDU verifyDefaultPINCommand = new CommandAPDU(0x00, INS_VERIFY, 0x00, SLOT_PIN, DEFAULT_PIN);
        response = simulator.transmitCommand(verifyDefaultPINCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "Unable to verify default PIN.");

        // Change the PIN
        // Format: Current PIN and new PIN
        ByteArrayOutputStream changeDefaultPINBytes = new ByteArrayOutputStream();
        changeDefaultPINBytes.write(DEFAULT_PIN);
        changeDefaultPINBytes.write(TEST_PIN);

        // Ensure that the PIN change operation return success
        CommandAPDU changeDefaultPINCommand = new CommandAPDU(0x00, INS_CHANGE_REFERENCE_DATA, 0x00, SLOT_PIN, changeDefaultPINBytes.toByteArray());
        response = simulator.transmitCommand(changeDefaultPINCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "Unable to change default PIN.");

        // Ensure the PIN metadata shows the PIN is no longer default
        response = simulator.transmitCommand(getPINMetadataCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "Unable to get metadata for PIN.");
        parsed = parser.parse(response.getData());
        isDefaultTag = parsed.find(TAG_DEFAULT_VALUE);
        assertNotNull(isDefaultTag, "Default status not present in PIN metadata.");
        assertEquals(0x00, isDefaultTag.getIntValue(), "Non-default PIN is still reported as default.");

        // Ensure that the default PIN no longer works, and that the counter decrements
        response = simulator.transmitCommand(verifyDefaultPINCommand);
        int counter = response.getSW2();
        assertEquals(SW1_INCORRECT_PIN, response.getSW1(), "PIN was not changed, but command returned success.");
        response = simulator.transmitCommand(verifyDefaultPINCommand);
        assertEquals(counter - 1, response.getSW2(), "Failed to decrement retries left counter on wrong PIN.");

        // Ensure that the new PIN works, and resets the counter
        CommandAPDU verifyNewPINCommand = new CommandAPDU(0x00, INS_VERIFY, 0x00, SLOT_PIN, TEST_PIN);
        response = simulator.transmitCommand(verifyNewPINCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "Unable to verify changed PIN.");
        response = simulator.transmitCommand(verifyDefaultPINCommand);
        assertEquals(counter, response.getSW2(), "Failed to reset retries left counter on correct PIN.");
    }

    @Test
    void TestVerifyAndSetPUK() throws IOException {
        ResponseAPDU response;
        BerTlvParser parser = new BerTlvParser();
        BerTlvs parsed;

        // Ensure the PUK metadata shows the PUK is default
        final CommandAPDU getPUKMetadataCommand = new CommandAPDU(0x00, INS_GET_METADATA, 0x00, SLOT_PUK);
        response = simulator.transmitCommand(getPUKMetadataCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "Unable to get metadata for PUK.");
        parsed = parser.parse(response.getData());
        BerTlv isDefaultTag = parsed.find(TAG_DEFAULT_VALUE);
        assertNotNull(isDefaultTag, "Default status not present in PUK metadata.");
        assertEquals(0x01, isDefaultTag.getIntValue(), "Default PUK is not reported as default.");

        // Verify the default PUK
        final CommandAPDU verifyDefaultPUKCommand = new CommandAPDU(0x00, INS_VERIFY, 0x00, SLOT_PUK, DEFAULT_PUK);
        response = simulator.transmitCommand(verifyDefaultPUKCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "Unable to verify default PUK.");

        // Change the PUK
        // Format: Current PUK and new PUK
        ByteArrayOutputStream changeDefaultPUKBytes = new ByteArrayOutputStream();
        changeDefaultPUKBytes.write(DEFAULT_PUK);
        changeDefaultPUKBytes.write(TEST_PIN);

        // Ensure that the PIN change operation return success
        CommandAPDU changeDefaultPUKCommand = new CommandAPDU(0x00, INS_CHANGE_REFERENCE_DATA, 0x00, SLOT_PUK, changeDefaultPUKBytes.toByteArray());
        response = simulator.transmitCommand(changeDefaultPUKCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "Unable to change default PUK.");

        // Ensure the PUK metadata shows the PUK is no longer default
        response = simulator.transmitCommand(getPUKMetadataCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "Unable to get metadata for PUK.");
        parsed = parser.parse(response.getData());
        isDefaultTag = parsed.find(TAG_DEFAULT_VALUE);
        assertNotNull(isDefaultTag, "Default status not present in PUK metadata.");
        assertEquals(0x00, isDefaultTag.getIntValue(), "Non-default PUK is still reported as default.");

        // Ensure that the default PUK no longer works, and that the counter decrements
        response = simulator.transmitCommand(verifyDefaultPUKCommand);
        int counter = response.getSW2();
        assertEquals(SW1_INCORRECT_PIN, response.getSW1(), "PUK was not changed, but command returned success.");
        response = simulator.transmitCommand(verifyDefaultPUKCommand);
        assertEquals(counter - 1, response.getSW2(), "Failed to decrement retries left counter on wrong PUK.");

        // Ensure that the new PUK works, and resets the counter
        CommandAPDU verifyNewPUKCommand = new CommandAPDU(0x00, INS_VERIFY, 0x00, SLOT_PUK, TEST_PUK);
        response = simulator.transmitCommand(verifyNewPUKCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "Unable to verify changed PUK.");
        response = simulator.transmitCommand(verifyDefaultPUKCommand);
        assertEquals(counter, response.getSW2(), "Failed to reset retries left counter on correct PUK.");
    }

    @Test
    void TestPukUsage() {

        ResponseAPDU response;
        BerTlvParser parser = new BerTlvParser();
        BerTlvs parsed;

        // Verify that the PIN is actually locked after the appropriate number of retries
        final CommandAPDU getPINMetadataCommand = new CommandAPDU(0x00, INS_GET_METADATA, 0x00, SLOT_PIN);
        response = simulator.transmitCommand(getPINMetadataCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "Unable to get metadata for PIN.");
        parsed = parser.parse(response.getData());
        BerTlv retriesTag = parsed.find(TAG_RETRIES);
        assertNotNull(retriesTag, "PIN slot metadata does not contain retries data.");

        int retryCounter = Byte.toUnsignedInt(retriesTag.getBytesValue()[0]);
        int remainingCounter = Byte.toUnsignedInt(retriesTag.getBytesValue()[1]);

        // Make sure the counts on applet initialization match
        assertEquals (remainingCounter, retryCounter, "Applet does not start with retry and remaining counts the same.");

        // Run out the PIN attempts
        final CommandAPDU verifyBadPINCommand = new CommandAPDU(0x00, INS_VERIFY, 0x00, SLOT_PIN, BAD_PIN);
        for (int i = (retryCounter - 1); i >= 0; i--) {
            response = simulator.transmitCommand(verifyBadPINCommand);
            assertEquals(SW1_INCORRECT_PIN, response.getSW1(), "Invalid PIN was accepted as valid.");
            assertEquals(i, response.getSW2() & 0x0F, "Retry count is not valid for verify.");

            // Verify the metadata matches reality
            response = simulator.transmitCommand(getPINMetadataCommand);
            assertEquals(SW_SUCCESS, response.getSW(), String.format("Unable to get metadata for PIN after %02X tries.", i));
            parsed = parser.parse(response.getData());
            retriesTag = parsed.find(TAG_RETRIES);
            assertNotNull(retriesTag, "PIN slot metadata does not contain retries data.");
            assertEquals(i, Byte.toUnsignedInt(retriesTag.getBytesValue()[1]), "Inaccurate retry counter for PIN");
        }

        // Make sure that the card is now locked
        final CommandAPDU verifyDefaultPINCommand = new CommandAPDU(0x00, INS_VERIFY, 0x00, SLOT_PIN, DEFAULT_PIN);
        response = simulator.transmitCommand(verifyDefaultPINCommand);
        assertEquals(SW_NO_TRIES_REMAINING, response.getSW(), String.format("PIN is not locked out when it should be.", 1));

        // PUK Verification
        final CommandAPDU getPUKMetadataCommand = new CommandAPDU(0x00, INS_GET_METADATA, 0x00, SLOT_PUK);
        final CommandAPDU resetPUKBadCommand = new CommandAPDU(0x00, INS_RESET_RETRY, 00, SLOT_PIN, RESET_PUK_BAD);
        final CommandAPDU resetPUKGoodCommand = new CommandAPDU(0x00, INS_RESET_RETRY, 00, SLOT_PIN, RESET_PUK_GOOD);

        // Ensure that a bad PUK does not unlock the card
        response = simulator.transmitCommand(getPUKMetadataCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "Unable to get metadata for PUK");
        parsed = parser.parse(response.getData());
        retriesTag = parsed.find(TAG_RETRIES);
        assertNotNull(retriesTag, "PUK slot metadata does not contain retries data.");
        int pukRetries = Byte.toUnsignedInt(retriesTag.getBytesValue()[1]);

        // Send the bad PUK command and verify the response
        response = simulator.transmitCommand(resetPUKBadCommand);
        assertEquals(0x63, response.getSW1(), "Invalid PUK returns the wrong status code.");
        assertEquals(pukRetries - 1, response.getSW2()&0x0F, "Invalid PUK returns the wrong counter in status code.");

        // Ensure the PIN slot is still locked
        response = simulator.transmitCommand(verifyDefaultPINCommand);
        assertEquals(SW_NO_TRIES_REMAINING, response.getSW(), "Bad PUK unlocks the PIN slot.");

        // Send the good PUK and make sure it works
        response = simulator.transmitCommand(resetPUKGoodCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "Correct PUK was not accepted.");
        response = simulator.transmitCommand(verifyDefaultPINCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "Default PIN was not accepted after PUK unlock.");

        // Run out the PIN, then the PUK
        for (int i = (retryCounter - 1); i >= 0; i--) {
            response = simulator.transmitCommand(verifyBadPINCommand);
            assertEquals(SW1_INCORRECT_PIN, response.getSW1(), "Invalid PIN works after PUK unlock.");
        }
        for (int i = (pukRetries - 1); i >= 0; i--) {
            response = simulator.transmitCommand(resetPUKBadCommand);
            assertEquals(SW1_INCORRECT_PIN, response.getSW1(), "Invalid PIN works after PUK unlock.");
            assertEquals (i, response.getSW2() & 0x0f, "PUK counter incorrect on reset.");
        }

        // Ensure the PUK doesn't work once retries are zero.
        response = simulator.transmitCommand(resetPUKGoodCommand);
        assertEquals(SW_NO_TRIES_REMAINING, response.getSW(), "PUK returns invalid response after retries exhausted.");

        // Ensure the PIN still doesn't work either
        response = simulator.transmitCommand(verifyDefaultPINCommand);
        assertEquals(SW_NO_TRIES_REMAINING, response.getSW(), "PIN returns invalid response after retries exhausted.");
    }

}
