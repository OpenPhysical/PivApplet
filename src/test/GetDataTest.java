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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static javax.crypto.Cipher.getInstance;
import static org.junit.jupiter.api.Assertions.*;

class GetDataTest {
    // Management slot (used for key management)
    final byte SLOT_MANAGEMENT = (byte) 0x9B;  // Management Key Slot
    // This tag represents dynamic authentication data
    final byte TAG_DYNAMIC_AUTHENTICATION = (byte) 0x7C;
    // These tags are used by general authenticate for challenge-response
    final byte TAG_AUTHENTICATE_CHALLENGE = (byte) 0x81;
    final byte TAG_AUTHENTICATE_RESPONSE = (byte) 0x82;
    // Used for generation
    final byte TAG_CRYPTO_ALG_IDENTIFIER_TEMPLATE = (byte) 0xAC;
    final byte TAG_CRYPTO_ALG_IDENTIFIER = (byte) 0x80;
    final byte TAG_CRYPTO_ALG_RSA1024 = (byte) 0x06;
    final byte TAG_CRYPTO_ALG_RSA2048 = (byte) 0x07;
    final byte TAG_CRYPTO_ALG_ECCP256 = (byte) 0x11;
    // Authenticates to the card
    final byte INS_GEN_AUTHENTICATE = (byte) 0x87;
    // Yubikey extension to get metadata for a slot
    final byte INS_GET_METADATA = (byte) 0xF7;
    // Generate an asymmetric key
    final byte INS_GEN_ASYM = (byte) 0x47;
    // Empty tags are a valid parameter for challenge, and will be filled on the response
    final byte LENGTH_EMPTY = (byte) 0x00;
    final byte LENGTH_CHALLENGE = (byte) 0x08;
    final byte[] CODE_SUCCESS = new byte[]{(byte) 0x90, (byte) 0x00};
    final byte[] CODE_REFERENCED_DATA_NOT_FOUND = new byte[]{(byte) 0x6A, (byte) 0x88};
    // Validation is performed using the default applet key
    final byte[] DEFAULT_MANAGEMENT_KEY = new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};
    CardSimulator simulator;
    AID appletAID = AIDUtil.create("A000000308000010000100");

    @BeforeEach
    void setUp() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // Re-initialize the simulator for each test
        simulator = new CardSimulator();

        // Install and select applet with no parameters
        simulator.installApplet(appletAID, PivApplet.class);
        simulator.selectApplet(appletAID);

        // Authenticate with the 9b management key
        byte[] commandData = new byte[]{TAG_DYNAMIC_AUTHENTICATION, (byte) 0x02, TAG_AUTHENTICATE_CHALLENGE, LENGTH_EMPTY};
        final CommandAPDU authenticateManagementKeyCommand = new CommandAPDU(0x00, INS_GEN_AUTHENTICATE, 0x00, SLOT_MANAGEMENT, commandData);
        ResponseAPDU response = simulator.transmitCommand(authenticateManagementKeyCommand);
        byte[] status = Arrays.copyOfRange(response.getBytes(), response.getBytes().length - 2, response.getBytes().length);
        assertArrayEquals(CODE_SUCCESS, status, String.format("Incorrect status response returned for authenticate: 0x%02X%02X", response.getSW1(), response.getSW2()));

        // Some sanity checking
        byte[] responseData = response.getData();
        assertEquals(TAG_DYNAMIC_AUTHENTICATION, responseData[0], "Card challenge missing dynamic authentication tag.");
        assertEquals((byte) 0x0A, responseData[1], "Card challenge response has invalid length.");
        assertEquals(TAG_AUTHENTICATE_CHALLENGE, responseData[2], "Card challenge response is missing the challenge tag.");
        assertEquals(LENGTH_CHALLENGE, responseData[3], "Card challenge has invalid length");

        // Extract the challenge
        byte[] challenge = Arrays.copyOfRange(responseData, 4, 12);
        assertEquals(0x08, challenge.length);

        // Calculate the response
        final SecretKeySpec managementKey = new SecretKeySpec(DEFAULT_MANAGEMENT_KEY, "TripleDES");
        Cipher managementKeyCipher = getInstance("TripleDES/ECB/NoPadding");
        managementKeyCipher.init(Cipher.ENCRYPT_MODE, managementKey);
        byte[] encryptedResponse = managementKeyCipher.doFinal(challenge);

        // Build the response APDU
        commandData = new byte[]{TAG_DYNAMIC_AUTHENTICATION, (byte) 0x0A, TAG_AUTHENTICATE_RESPONSE, LENGTH_CHALLENGE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        for (int i = 0; i < LENGTH_CHALLENGE; i++) {
            commandData[i + 4] = encryptedResponse[i];
        }
        final CommandAPDU authenticateManagementKeyResponseCommand = new CommandAPDU(0x00, INS_GEN_AUTHENTICATE, 0x00, SLOT_MANAGEMENT, commandData);
        response = simulator.transmitCommand(authenticateManagementKeyResponseCommand);
        assertArrayEquals(CODE_SUCCESS, response.getBytes(), "Unable to authenticate with default management key.");
    }

    @Test
    void TestGetMetadata() {
        // All slots supported by the YubiKey
        final byte[] allSlots = new byte[]{(byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83, (byte) 0x84, (byte) 0x85, (byte) 0x86, (byte) 0x87, (byte) 0x88, (byte) 0x89, (byte) 0x8A, (byte) 0x8B, (byte) 0x8C, (byte) 0x8D, (byte) 0x8E, (byte) 0x8F, (byte) 0x90, (byte) 0x91, (byte) 0x92, (byte) 0x93, (byte) 0x94, (byte) 0x95, (byte) 0x9A, (byte) 0x9B, (byte) 0x9C, (byte) 0x9D, (byte) 0x9E, (byte) 0xF9};

        final byte[] missingSlots = new byte[]{(byte) 0x82, (byte) 0x83, (byte) 0x84, (byte) 0x85, (byte) 0x86, (byte) 0x87, (byte) 0x88, (byte) 0x89, (byte) 0x8A, (byte) 0x8B, (byte) 0x8C, (byte) 0x8D, (byte) 0x8E, (byte) 0x8F, (byte) 0x90, (byte) 0x91, (byte) 0x92, (byte) 0x93, (byte) 0x94, (byte) 0x95, (byte) 0x9A, (byte) 0x9C, (byte) 0x9D, (byte) 0x9E, (byte) 0xF9};

        // First byte is PIN: 0 (default) Second byte is 1 (never), because we don't have touch.
        // This is also what the stock YubiKey sets on the 9B management key.
        final byte[] defaultTouchPolicy = new byte[]{(byte) 0x00, (byte) 0x01};
        final byte[] alwaysTouchPolicy = new byte[]{(byte) 0x03, (byte) 0x01};
        final byte[] neverTouchPolicy = new byte[]{(byte)0x01, (byte)0x01};

        // Go through all the default empty slots, and fill them.
        for (byte slot : missingSlots) {
            final CommandAPDU getSlotMetadataCommand = new CommandAPDU(0x00, INS_GET_METADATA, 0x00, slot);
            ResponseAPDU response = simulator.transmitCommand(getSlotMetadataCommand);

            // Missing slots should all return 0x6A88 (Referenced data not found)
            assertArrayEquals(CODE_REFERENCED_DATA_NOT_FOUND, response.getBytes(), String.format("Slot %02X is not empty, or empty slot does not return 0x6A88 (0x%02X%02X returned).", slot, response.getSW1(), response.getSW2()));

            // Fill them with an 1024-bit RSA key (to avoid needing to chain the APDUs)
            final byte[] commandData = new byte[]{TAG_CRYPTO_ALG_IDENTIFIER_TEMPLATE, 0x03, TAG_CRYPTO_ALG_IDENTIFIER, 0x01, TAG_CRYPTO_ALG_RSA1024};
            final CommandAPDU generateKeyCommand = new CommandAPDU(0x00, INS_GEN_ASYM, 00, slot, commandData);
            response = simulator.transmitCommand(generateKeyCommand);
            final byte[] status = new byte[]{(byte) response.getSW1(), (byte) response.getSW2()};
            assertArrayEquals(CODE_SUCCESS, status, "Unable to execute generate on slot.");
        }

        // Verify that the proper metadata tags are returned
        for (byte slot : allSlots) {
            final byte[] expectedTags = tagsForSlot(slot);
            final CommandAPDU getSlotMetadataCommand = new CommandAPDU(0x00, INS_GET_METADATA, 0x00, slot);
            final ResponseAPDU response = simulator.transmitCommand(getSlotMetadataCommand);
            final byte[] status = new byte[]{(byte) response.getSW1(), (byte) response.getSW2()};
            assertArrayEquals(CODE_SUCCESS, status, String.format("Incorrect status response returned for get metadata for slot %02x: 0x%02X%02X", slot, response.getSW1(), response.getSW2()));

            BerTlvParser parser = new BerTlvParser();
            BerTlvs parsed = parser.parse(response.getData());
            for (byte tag : expectedTags) {
                final BerTag searchTag = new BerTag(tag);
                final BerTlv searchValue = parsed.find(searchTag);
                assertNotNull(searchValue, String.format("Missing tag %02X in getMetaData response for slot %02X", tag, slot));

                // Ensure the algorithm tag is set properly if present
                if (tag == 0x01) {
                    // For PIN and PUK, this should be 0xFF
                    if ((byte) 0x80 == slot || (byte) 0x81 == slot) {
                        assertEquals(searchValue.getIntValue(), 0xFF);
                    } else if ((byte)0x9B == slot) {
                        // This should be 3DES
                        // @todo handle AES keys
                        assertEquals(searchValue.getIntValue(), 0x03);
                    }
                } else if (tag == 0x02) {
                    // The PIN policy should be default, and the touch policy should be never
                    byte[] policyBytes = searchValue.getBytesValue();
                    assertEquals(2, policyBytes.length, String.format("Pin and touch policy have incorrect length for slot %02X.", slot));

                    // The goal of this metadata is largely to support attestation and policy checks.  The default for yubikeys is PIN once, touch never.
                    // Any policy other than that should be made explicit to ensure that attestation certs aren't misleading
                    if ((byte)0x9C == slot) {
                        assertArrayEquals(alwaysTouchPolicy, policyBytes, String.format("PIN policy metadata incorrect for slot %02X.  Expected: 0x0001, Actual: %02X%02X", slot, policyBytes[0], policyBytes[1]));
                    } else if ((byte)0x9e == slot) {
                        assertArrayEquals(neverTouchPolicy, policyBytes, String.format("PIN policy metadata incorrect for slot %02X.  Expected: 0x0001, Actual: %02X%02X", slot, policyBytes[0], policyBytes[1]));
                    } else {
                        assertArrayEquals(defaultTouchPolicy, policyBytes, String.format("PIN policy metadata incorrect for slot %02X.  Expected: 0x0001, Actual: %02X%02X", slot, policyBytes[0], policyBytes[1]));
                    }
                }

            }

            assertEquals(1, 1);
        }
    }

    // See https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/metadata.html
    byte[] tagsForSlot(byte slot) {
        if (slot >= (byte) 0x80 && slot <= (byte) 0x81) {
            // PIN and PUK
            return new byte[]{0x01, 0x05, 0x06};
        } else if ((byte) 0x9B == slot) {
            // Management Key
            return new byte[]{0x01, 0x02, 0x05};
        } else if (slot >= (byte) 0x82 && slot <= (byte) 0x95) {
            // Retired Keys
            return new byte[]{0x01, 0x02, 0x03, 0x04};
        } else if ((byte) 0x9A == slot || (slot >= (byte) 0x9C && slot <= (byte) 0x9E)) {
            // Authentication, Signing, Key Management, Card Auth
            return new byte[]{0x01, 0x02, 0x03, 0x04};
        } else if ((byte) 0xF9 == slot) {
            // Attestation
            return new byte[]{0x01, 0x02, 0x03, 0x04};
        }

        throw new IllegalArgumentException("Invalid slot specified.");
    }
}