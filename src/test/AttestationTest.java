package test;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AttestationTest {
    CardSimulator simulator;
    AID appletAID = AIDUtil.create("A000000308000010000100");

    @BeforeEach
    void setUp() {
        // Re-initialize the simulator for each test
        simulator = new CardSimulator();
    }

    @Test
    void TestGetFASCN() {

    }
}