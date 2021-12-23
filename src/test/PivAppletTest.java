package test;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import net.cooperi.pivapplet.PivApplet;
import net.cooperi.pivapplet.TlvReader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class PivAppletTest {
    CardSimulator simulator;
    AID appletAID;

    @BeforeEach
    void setUp() {
        simulator = new CardSimulator();
        appletAID = AIDUtil.create("A000000308000010000100");
        simulator.installApplet(appletAID, PivApplet.class);
        simulator.selectApplet(appletAID);
    }

    @Test
    void install() {

    }

    @Test
    void TestSelectResponse() {
        final byte[] PIV_AID = {
                (byte)0xa0, (byte)0x00, (byte)0x00, (byte)0x03, (byte)0x08,
                (byte)0x00, (byte)0x00, (byte)0x10, (byte)0x00, (byte)0x01,
                (byte)0x00
        };

        // See Special Publication 800-73
        // 2.3.3.1.1 SELECT APPLET/SELECT OBJECT APDU
        byte[] response = simulator.selectAppletWithResult(appletAID);
        byte[] responseAid = Arrays.copyOfRange(response, 5, 5 + PIV_AID.length);

        assertEquals(0x61,response[0]);
        assertArrayEquals(PIV_AID, responseAid);
    }
}