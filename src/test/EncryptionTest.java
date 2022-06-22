package test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvBuilder;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;

import net.cooperi.pivapplet.PivApplet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import javacard.framework.AID;

public class EncryptionTest {
    AID appletAID = AIDUtil.create("A000000308000010000100");
    CardSimulator simulator = new CardSimulator();

    final byte INS_IMPORT_ASYM = (byte)0xFE;

    final byte ALG_RSA_1024 = (byte)0x06;

    final byte SLOT_9A = (byte)0x9A;

    final int SW_SUCCESS = 0x9000;

    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static byte[] leftTrimByteArray(byte[] input) {
        int count = 0;
        for (int i = 0; i < input.length; i++) {
            if (input[i] != 0x00) {
                break;
            }
            count++;
        }
        byte[] output = new byte[input.length - count];
        for (int i = 0; i < (output.length); i++) {
            output[i] = input[i+count];
        }

        return output;
    }

    @BeforeEach
    void setUp() throws IOException {
        // Re-initialize the simulator for each test
        simulator.reset();

        // Install the applet with no parameters and select it
        simulator.installApplet(appletAID, PivApplet.class);
        simulator.selectApplet(appletAID);

        // Install some keys for testing
        InputStream inputStream = new FileInputStream("test/keys/rsa_1024.key");

        // More than large enough to read any 2048 bit key
        byte[] buffer = new byte[16384];
        int len = 0;
        len = inputStream.read(buffer);
        if (len > 8192) {
            throw new IOException("File is way too large to be a RSA key.");
        }
        inputStream.close();
        byte[] apduData = processRSAKey(buffer);

        CommandAPDU writeRsa1024Command = new CommandAPDU(0x00, INS_IMPORT_ASYM, ALG_RSA_1024, SLOT_9A, apduData);
        ResponseAPDU response = simulator.transmitCommand(writeRsa1024Command);
        assertEquals(SW_SUCCESS, response.getSW());

        System.out.println("Encoded: " + byteArrayToHex(apduData));
    }

    @Test
    void testDecrypt() {

    }

    @Test
    void testKeyAgreement() {

    }

    @Test
    void testManagementMutualAuth() {

    }

    @Test
    void testSign() {

    }

    @Test
    void testGenerateKeypair() {

    }

    @Test
    void testImportAsymmetric() {

    }

    /**
     * Process an RSA key from PKCS1 to APDU format
     * Input:
     * Version, Modulus, publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient
     * Output (Tag, Length, Value):
     * 0x01 Prime1, 0x02 Prime2, 0x03 Exponent1, 0x04 Exponent2, 0x05 Coefficient
     *
     * @param inputData Input ASN-1 data from the loaded file
     */
    byte[] processRSAKey(byte[] inputData) throws IOException {
        // Extract the fields from the key file
        BerTlvParser parser = new BerTlvParser();
        BerTlvs parsed = parser.parse(inputData);
        List<BerTlv> data = parsed.find(new BerTag(0x30)).getValues();
        byte[] prime1 = leftTrimByteArray(data.get(0x04).getBytesValue());
        byte[] prime2 = leftTrimByteArray(data.get(0x05).getBytesValue());
        byte[] exponent1 = leftTrimByteArray(data.get(0x06).getBytesValue());
        byte[] exponent2 = leftTrimByteArray(data.get(0x07).getBytesValue());
        byte[] coefficient = leftTrimByteArray(data.get(0x08).getBytesValue());

        // Create the formatted APDU
        BerTlvBuilder tlvBuilder = new BerTlvBuilder();
        tlvBuilder.addBerTlv(new BerTlv(new BerTag(0x01), prime1));
        tlvBuilder.addBerTlv(new BerTlv(new BerTag(0x02), prime2));
        tlvBuilder.addBerTlv(new BerTlv(new BerTag(0x03), exponent1));
        tlvBuilder.addBerTlv(new BerTlv(new BerTag(0x04), exponent2));
        tlvBuilder.addBerTlv(new BerTlv(new BerTag(0x05), coefficient));

        return tlvBuilder.buildArray();
    }
}
