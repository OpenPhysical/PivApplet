package test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static javax.crypto.Cipher.getInstance;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;
import com.payneteasy.tlv.HexUtil;

import net.cooperi.pivapplet.PivApplet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import javacard.framework.AID;

class GetPutDataTest {
    // Management slot (used for key management)
    final byte SLOT_MANAGEMENT = (byte) 0x9B;  // Management Key Slot

    // This tag represents dynamic authentication data
    final byte TAG_DYNAMIC_AUTHENTICATION = (byte) 0x7C;

    // This tag represents the printed information on the card
    final byte TAG_PRINTED_DATA = (byte) 0x09;

    // These tags are used by general authenticate for challenge-response
    final byte TAG_AUTHENTICATE_CHALLENGE = (byte) 0x81;
    final byte TAG_AUTHENTICATE_RESPONSE = (byte) 0x82;

    // Used for generation
    final byte TAG_CRYPTO_ALG_IDENTIFIER_TEMPLATE = (byte) 0xAC;
    final byte TAG_CRYPTO_ALG_IDENTIFIER = (byte) 0x80;
    final byte TAG_CRYPTO_ALG_RSA1024 = (byte) 0x06;
    final byte TAG_CRYPTO_ALG_RSA2048 = (byte) 0x07;
    final byte TAG_CRYPTO_ALG_ECCP256 = (byte) 0x11;

    // Generate an asymmetric key
    final byte INS_GEN_ASYM = (byte) 0x47;

    // Authenticates to the card
    final byte INS_GEN_AUTHENTICATE = (byte) 0x87;

    // Get and put data from the card
    final byte INS_GET_DATA = (byte) 0xCB;
    final byte INS_PUT_DATA = (byte) 0xDB;

    // Yubikey extension to get metadata for a slot
    final byte INS_GET_METADATA = (byte) 0xF7;

    // Empty tags are a valid parameter for challenge, and will be filled on the response
    final byte LENGTH_EMPTY = (byte) 0x00;
    final byte LENGTH_CHALLENGE = (byte) 0x08;

    // Validation is performed using the default applet key
    final byte[] DEFAULT_MANAGEMENT_KEY = new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
            (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
            (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
            (byte) 0x06, (byte) 0x07, (byte) 0x08};

    // Status Words
    final int SW_SUCCESS = 0x9000;
    final int SW_REFERENCED_DATA_NOT_FOUND = 0x6A88;
    final int SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982;
    final int SW_FILE_NOT_FOUND = 0x6A82;

    // PIV data tag
    final byte TAG_PIV_IDENTIFIER_PREFIX = (byte) 0x5F;
    final byte TAG_PIV_IDENTIFIER_SUFFIX = (byte) 0xC1;
    final byte TAG_PIV_VENDOR_SUFFIX = (byte) 0xFF;
    final byte TAG_PIV_DATA = (byte) 0x5C;
    final byte TAG_PIV_OBJECT_DATA = (byte) 0x53;

    // Yubikey-specific
    final byte TAG_YUBIKEY_ADMIN = (byte) 0x00;

    final byte INS_VERIFY = (byte) 0x20; // Verifies PIN
    final byte SLOT_PIN = (byte) 0x80;
    final byte APPLET_PIN_PADDING = (byte) 0xFF;
    final byte[] DEFAULT_PIN = new byte[]{'1', '2', '3', '4', '5', '6', APPLET_PIN_PADDING, APPLET_PIN_PADDING};

    CardSimulator simulator = new CardSimulator();
    AID appletAID = AIDUtil.create("A000000308000010000100");

    @BeforeEach
    void setUp() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        // Re-initialize the simulator for each test
        simulator.resetRuntime();

        // Install and select applet with no parameters
        simulator.installApplet(appletAID, PivApplet.class);
        simulator.selectApplet(appletAID);

        // Authenticate with the 9b management key
        byte[] commandData = new byte[]{TAG_DYNAMIC_AUTHENTICATION, (byte) 0x02, TAG_AUTHENTICATE_CHALLENGE,
                LENGTH_EMPTY};
        final CommandAPDU authenticateManagementKeyCommand = new CommandAPDU(0x00, INS_GEN_AUTHENTICATE, 0x00,
                SLOT_MANAGEMENT, commandData);
        ResponseAPDU response = simulator.transmitCommand(authenticateManagementKeyCommand);
        assertEquals(SW_SUCCESS, response.getSW(), String.format("Incorrect status response returned for " +
                "authenticate: 0x%04X", response.getSW()));

        // Some sanity checking
        byte[] responseData = response.getData();
        assertEquals(TAG_DYNAMIC_AUTHENTICATION, responseData[0], "Card challenge missing dynamic authentication tag.");
        assertEquals((byte) 0x0A, responseData[1], "Card challenge response has invalid length.");
        assertEquals(TAG_AUTHENTICATE_CHALLENGE, responseData[2], "Card challenge response is missing the challenge " +
                "tag.");
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
        commandData = new byte[]{TAG_DYNAMIC_AUTHENTICATION, (byte) 0x0A, TAG_AUTHENTICATE_RESPONSE, LENGTH_CHALLENGE
                , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        for (int i = 0; i < LENGTH_CHALLENGE; i++) {
            commandData[i + 4] = encryptedResponse[i];
        }
        final CommandAPDU authenticateManagementKeyResponseCommand = new CommandAPDU(0x00, INS_GEN_AUTHENTICATE, 0x00
                , SLOT_MANAGEMENT, commandData);
        response = simulator.transmitCommand(authenticateManagementKeyResponseCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "Unable to authenticate with default management key.");
    }

    @Test
    void TestGetKeyMetadata() {
        // All slots supported by the YubiKey
        final byte[] allSlots = new byte[]{(byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83, (byte) 0x84,
                (byte) 0x85, (byte) 0x86, (byte) 0x87, (byte) 0x88, (byte) 0x89, (byte) 0x8A, (byte) 0x8B,
                (byte) 0x8C, (byte) 0x8D, (byte) 0x8E, (byte) 0x8F, (byte) 0x90, (byte) 0x91, (byte) 0x92,
                (byte) 0x93, (byte) 0x94, (byte) 0x95, (byte) 0x9A, (byte) 0x9B, (byte) 0x9C, (byte) 0x9D,
                (byte) 0x9E, (byte) 0xF9};

        // These slots don't have default values, and will need to have values supplied
        final byte[] missingSlots = new byte[]{(byte) 0x82, (byte) 0x83, (byte) 0x84, (byte) 0x85, (byte) 0x86,
                (byte) 0x87, (byte) 0x88, (byte) 0x89, (byte) 0x8A, (byte) 0x8B, (byte) 0x8C, (byte) 0x8D,
                (byte) 0x8E, (byte) 0x8F, (byte) 0x90, (byte) 0x91, (byte) 0x92, (byte) 0x93, (byte) 0x94,
                (byte) 0x95, (byte) 0x9A, (byte) 0x9C, (byte) 0x9D, (byte) 0x9E, (byte) 0xF9};

        // First byte is PIN: 0 (default) Second byte is 1 (never), because we don't have touch.
        // This is also what the stock YubiKey sets on the 9B management key.
        final byte[] defaultTouchPolicy = new byte[]{(byte) 0x00, (byte) 0x01};
        final byte[] alwaysTouchPolicy = new byte[]{(byte) 0x03, (byte) 0x01};
        final byte[] neverTouchPolicy = new byte[]{(byte) 0x01, (byte) 0x01};
        final byte[] oneTimeTouchPolicy = new byte[]{(byte) 0x02, (byte) 0x01};
        final int DEFAULT_PIN_RETRIES = 0x05;
        final int DEFAULT_PUK_RETRIES = 0x03;

        // Go through all the default empty slots, and fill them.
        for (byte slot : missingSlots) {
            final CommandAPDU getSlotMetadataCommand = new CommandAPDU(0x00, INS_GET_METADATA, 0x00, slot);
            ResponseAPDU response = simulator.transmitCommand(getSlotMetadataCommand);

            // Missing slots should all return 0x6A88 (Referenced data not found)
            assertEquals(SW_REFERENCED_DATA_NOT_FOUND, response.getSW(), String.format("Slot %02X is not " +
                    "empty, or empty slot does not return 0x6A88 (0x%04X returned).", slot, response.getSW()));

            // Fill them with an 1024-bit RSA key (to avoid needing to chain the APDUs)
            final byte[] commandData = new byte[]{TAG_CRYPTO_ALG_IDENTIFIER_TEMPLATE, 0x03, TAG_CRYPTO_ALG_IDENTIFIER
                    , 0x01, TAG_CRYPTO_ALG_RSA1024};
            final CommandAPDU generateKeyCommand = new CommandAPDU(0x00, INS_GEN_ASYM, 0x00, slot, commandData);
            response = simulator.transmitCommand(generateKeyCommand);
            assertEquals(SW_SUCCESS, response.getSW(), "Unable to execute generate on slot.");
        }

        // Verify that the proper metadata tags are returned
        for (byte slot : allSlots) {
            final byte[] expectedTags = tagsForSlot(slot);
            final CommandAPDU getSlotMetadataCommand = new CommandAPDU(0x00, INS_GET_METADATA, 0x00, slot);
            final ResponseAPDU response = simulator.transmitCommand(getSlotMetadataCommand);
            assertEquals(SW_SUCCESS, response.getSW(), String.format("Incorrect status response returned for get " +
                    "metadata for slot %02X: 0x%04X", slot, response.getSW()));

            BerTlvParser parser = new BerTlvParser();
            BerTlvs parsed = parser.parse(response.getData());
            for (byte tag : expectedTags) {
                final BerTag searchTag = new BerTag(tag);
                final BerTlv searchValue = parsed.find(searchTag);
                assertNotNull(searchValue, String.format("Missing tag %02X in getMetaData response for slot %02X",
                        tag, slot));

                if (tag == 0x01) {
                    // Ensure the algorithm tag is set properly if present
                    // For PIN and PUK, this should be 0xFF
                    if ((byte) 0x80 == slot || (byte) 0x81 == slot) {
                        assertEquals(searchValue.getIntValue(), 0xFF);
                    } else if ((byte) 0x9B == slot) {
                        // This should be 3DES
                        // @todo handle AES keys
                        assertEquals(searchValue.getIntValue(), 0x03);
                    }
                } else if (tag == 0x02) {
                    // The PIN policy should be default, and the touch policy should be never
                    byte[] policyBytes = searchValue.getBytesValue();
                    assertEquals(2, policyBytes.length, String.format("Pin and touch policy have incorrect length for" +
                            " slot %02X.", slot));

                    // The goal of this metadata is largely to support attestation and policy checks.  The default
                    // for yubikeys is PIN once, touch never.
                    // Any policy other than that should be made explicit to ensure that attestation certs aren't
                    // misleading
                    if ((byte) 0x9C == slot) {
                        // The signature slot defaults to always require
                        assertArrayEquals(alwaysTouchPolicy, policyBytes, String.format("PIN policy metadata " +
                                        "incorrect for slot %02X.  Expected: 0x0301, Actual: %02X%02X", slot,
                                policyBytes[0],
                                policyBytes[1]));
                    } else if ((byte) 0x9e == slot) {
                        // The card authentication key slot defaults to never require
                        assertArrayEquals(neverTouchPolicy, policyBytes, String.format("PIN policy metadata incorrect" +
                                        " for slot %02X.  Expected: 0x0101, Actual: %02X%02X", slot, policyBytes[0],
                                policyBytes[1]));
                    } else if ((byte) 0x9b == slot) {
                        // The management key defaults to "default" for the PIN requirement, but that actually means
                        // "never" (consistent with PIV reqs)
                        assertArrayEquals(defaultTouchPolicy, policyBytes, String.format("PIN policy metadata " +
                                        "incorrect for slot %02X.  Expected: 0x0001, Actual: %02X%02X", slot,
                                policyBytes[0],
                                policyBytes[1]));
                    } else {
                        // Everything else defaults to "PIN once"
                        assertArrayEquals(oneTimeTouchPolicy, policyBytes, String.format("PIN policy metadata " +
                                        "incorrect for slot %02X.  Expected: 0x0201, Actual: %02X%02X", slot,
                                policyBytes[0],
                                policyBytes[1]));
                    }
                } else if (tag == 0x03) {
                    // Generated vs imported flag.
                    // As every single key is a result of a generate option, they should all have the value 0x01
                    // (generated)
                    assertEquals(0x01, searchValue.getIntValue(), String.format("Generated key in slot %02X does not " +
                            "have the generated flag set (value: %02X).", slot, searchValue.getIntValue()));
                } else if (tag == 0x04) {
                    // Public key
                    byte[] publicKeyValue = searchValue.getBytesValue();

                    // Sanity checking
                    // Format: 81 || length || modulus || 82 || length || public exponent
                    assertEquals((byte) 0x81, publicKeyValue[0]);
                    int modulusLength = Byte.toUnsignedInt(publicKeyValue[1]);
                    assertNotEquals(0, modulusLength, "Generated RSA modulus must be non-zero.");

                    // Check for the public exponent tag
                    assertEquals((byte) 0x82, publicKeyValue[modulusLength + 2]);
                    int exponentLength = Byte.toUnsignedInt(publicKeyValue[modulusLength + 3]);
                    assertNotEquals(0, exponentLength, "Generated RSA exponent must be non-zero.");
                    int expectedLength = modulusLength + exponentLength + 4;
                    assertEquals(publicKeyValue.length, expectedLength, "GenAsym() returns invalid public key data.");
                } else if (tag == 0x05) {
                    // Default PIN value
                    // All PINs should be default PIN values, so ensure that the metadata returns such
                    assertEquals(0x01, searchValue.getIntValue(), String.format("Default PIN/PUK in slot %02X is " +
                            "reporting as non-default.", slot));
                } else if (tag == 0x06) {
                    // Retry data
                    if (slot == (byte) 0x80) {
                        // PIN
                        assertEquals(DEFAULT_PIN_RETRIES, searchValue.getBytesValue()[0], String.format("PIN has " +
                                        "unexpected retries (expected: %02x, actual: %02x", DEFAULT_PIN_RETRIES,
                                searchValue.getBytesValue()[0]));
                        assertEquals(DEFAULT_PIN_RETRIES, searchValue.getBytesValue()[1], String.format("PIN has " +
                                        "unexpected remaining (expected: %02x, actual: %02x", DEFAULT_PIN_RETRIES,
                                searchValue.getBytesValue()[1]));
                        assertEquals(2, searchValue.getBytesValue().length, "PIN retry metadata has unexpected length" +
                                ".");
                    } else if (slot == (byte) 0x81) {
                        // PUK
                        assertEquals(DEFAULT_PUK_RETRIES, searchValue.getBytesValue()[0], String.format("PUK has " +
                                        "unexpected retries (expected: %02x, actual: %02x", DEFAULT_PUK_RETRIES,
                                searchValue.getBytesValue()[0]));
                        assertEquals(DEFAULT_PUK_RETRIES, searchValue.getBytesValue()[1], String.format("PUK has " +
                                        "unexpected remaining (expected: %02x, actual: %02x", DEFAULT_PUK_RETRIES,
                                searchValue.getBytesValue()[1]));
                        assertEquals(2, searchValue.getBytesValue().length, "PUK retry metadata has unexpected length" +
                                ".");
                    }
                }
            }
        }
    }

    @Test
    void testDefaultManagementData() {
        // From https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html#encoded-admin-data
        // This data is present for backwards compatibility, but as all fields are optional we don't include any of
        // them.

        final byte[] getDataParameter = new byte[]{TAG_PIV_DATA, (byte) 0x03, TAG_PIV_IDENTIFIER_PREFIX,
                TAG_PIV_VENDOR_SUFFIX, TAG_YUBIKEY_ADMIN};
        final CommandAPDU getDataCommand = new CommandAPDU(0x00, INS_GET_DATA, 0x3F, 0xFF, getDataParameter);

        final byte[] expectedResponse = new byte[]{TAG_PIV_OBJECT_DATA, (byte) 0x02, (byte) 0x80, (byte) 0x00};
        final ResponseAPDU response = simulator.transmitCommand(getDataCommand);
        assertEquals(SW_SUCCESS, response.getSW(), String.format("Get management data failed with SW 0x%04X",
                response.getSW()));
        assertArrayEquals(expectedResponse, response.getData());
    }

    @Test
    void testCertificateEncoding() {
        // From https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html#encoded-certificate
        // If the certificate retrieved is the attestation statement, it is returned encoded as follows.
        // 53 L1 70 L2 --X.509 certificate--
        // All other certificates are returned as specified in the PIV standard:
        // 53 L1 70 L2 --X.509 certificate-- 71 01 00 (compression) FE 00 (LRC)

        // Go through all the elements and fill them.  Other than BITGT, tags start with 0x5FC1
        byte[] elements = new byte[]{(byte) 0x05, (byte) 0x0A, (byte) 0x0B, (byte) 0x01, (byte) 0x0D, (byte) 0x0E,
                (byte) 0x0F, (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15,
                (byte) 0x16, (byte) 0x17, (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B, (byte) 0x1C,
                (byte) 0x1D, (byte) 0x1E, (byte) 0x1F, (byte) 0x20, (byte) 0x09, (byte) 0x06, (byte) 0x0C,
                (byte) 0x21, (byte) 0x08, (byte) 0x03, (byte) 0x22, (byte) 0x23};

        for (byte element : elements) {
            // Fill the element into the tag
            byte[] tag = new byte[]{TAG_PIV_IDENTIFIER_PREFIX, TAG_PIV_IDENTIFIER_SUFFIX, (byte) 0x00};
            tag[2] = element;

            byte[] getDataParameter = new byte[]{TAG_PIV_DATA, (byte) 0x03, TAG_PIV_IDENTIFIER_PREFIX,
                    TAG_PIV_IDENTIFIER_SUFFIX
                    , element};
            final CommandAPDU getDataCommand = new CommandAPDU(0x00, INS_GET_DATA, 0x3F, 0xFF, getDataParameter);
            final ResponseAPDU response = simulator.transmitCommand(getDataCommand);

            // @todo finish this
            assertEquals(1, 1);
        }
    }

    @Test
    void testPINProtectedManagementKey() throws IOException {
        // 0x88 = PIVMan Protected Data
        // 0x89 = Management Key
        // 0x88 0x1A 0x89 0x18 [MGMT KEY]
        final byte[] managementData = new byte[]{(byte) 0x88, (byte) 0x1A, (byte) 0x89, (byte) 0x18, (byte) 0x01,
                (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01,
                (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x01,
                (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08};

        //  Yubikey stores the management key in the printed data area
        //  5C - Tag List
        //  03 - Len
        //  5F C1 09 - Printed Data
        byte[] getDataParameter = new byte[]{TAG_PIV_DATA, (byte) 0x03, TAG_PIV_IDENTIFIER_PREFIX,
                TAG_PIV_IDENTIFIER_SUFFIX, TAG_PRINTED_DATA};
        final CommandAPDU getPrintedDataCommand = new CommandAPDU(0x00, INS_GET_DATA, 0x3F, 0xFF, getDataParameter);

        // Ensure that security status is properly set if the PIN was not entered
        ResponseAPDU response = simulator.transmitCommand(getPrintedDataCommand);
        assertEquals(SW_SECURITY_STATUS_NOT_SATISFIED, response.getSW(), "Get Data on printed information must return" +
                " 0x6982 (Security Status Not Satisfied) until PIN is entered.");

        // Enter the PIN, then make sure that the file is not found (default state)
        final CommandAPDU verifyDefaultPINCommand = new CommandAPDU(0x00, INS_VERIFY, 0x00, SLOT_PIN, DEFAULT_PIN);
        response = simulator.transmitCommand(verifyDefaultPINCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "PIN verification failed.  It shouldn't.");
        response = simulator.transmitCommand(getPrintedDataCommand);
        assertEquals(SW_FILE_NOT_FOUND, response.getSW(), "Get Data on printed information must return " +
                "0x6A82 (Not Found) once PIN is entered for newly installed applet.");

        // Try to write the printed object without the management key.  This must fail.
        ByteArrayOutputStream writePrintedObjectBytes = new ByteArrayOutputStream();

        // 0x5c 0x03        [Tag List] [Tag Len]
        //  0x5f 0xc1 0x09  PIV Printed Data
        writePrintedObjectBytes.write(new byte[]{
                TAG_PIV_DATA, (byte) 0x03, TAG_PIV_IDENTIFIER_PREFIX, TAG_PIV_IDENTIFIER_SUFFIX, TAG_PRINTED_DATA});

        // 0x53 [LEN] [DATA]
        writePrintedObjectBytes.write(TAG_PIV_OBJECT_DATA);
        writePrintedObjectBytes.write((byte) managementData.length);
        writePrintedObjectBytes.write(managementData);

        // Write the printed data
        final byte[] putDataPayload = writePrintedObjectBytes.toByteArray();
        final CommandAPDU putPrintedDataCommand = new CommandAPDU(0x00, INS_PUT_DATA, 0x3F, 0xFF, putDataPayload);
        response = simulator.transmitCommand(putPrintedDataCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "PUT DATA on printed information field must " +
                "require authentication with the management key.");

        // Read it back and verify
        ByteArrayOutputStream readPrintedObjectBytes = new ByteArrayOutputStream();
        readPrintedObjectBytes.write(TAG_PIV_OBJECT_DATA);
        readPrintedObjectBytes.write((byte) managementData.length);
        readPrintedObjectBytes.write(managementData);

        response = simulator.transmitCommand(getPrintedDataCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "Get Data on printed information must return 0x9000 (success) " +
                "after being written");
        byte[] getPrintedDataResponse = response.getData();
        assertArrayEquals(readPrintedObjectBytes.toByteArray(), getPrintedDataResponse, "Response data must match and" +
                " be properly formatted.");

        // Reset the runtime to make sure that the command requires authentication
        simulator.resetRuntime();
        simulator.installApplet(appletAID, PivApplet.class);
        simulator.selectApplet(appletAID);

        // PIN should be insufficient to call this command, so give it a try
        response = simulator.transmitCommand(verifyDefaultPINCommand);
        assertEquals(SW_SUCCESS, response.getSW(), "PIN verification failed.  It shouldn't.");

        // Try putting the data authenticated only with the PIN
        response = simulator.transmitCommand(putPrintedDataCommand);
        assertEquals(SW_SECURITY_STATUS_NOT_SATISFIED, response.getSW(), "PUT DATA on printed information field must " +
                "require authentication with the management key.");
    }

    @Test
    void testGetFirmwareVersion() {

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