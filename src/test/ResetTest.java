package test;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import net.cooperi.pivapplet.PivApplet;

import org.junit.jupiter.api.BeforeEach;

import javacard.framework.AID;

public class ResetTest {
	AID appletAID = AIDUtil.create("A000000308000010000100");
	CardSimulator simulator = new CardSimulator();

	@BeforeEach
	void setUp() {
		// Re-initialize the simulator for each test
		simulator.reset();

		// Install the applet with no parameters and select it
		simulator.installApplet(appletAID, PivApplet.class);
		simulator.selectApplet(appletAID);
	}

	void EnsurePinMustBeBlocked() {

	}

	void EnsurePukMustBeBlocked() {

	}

	void EnsureKeysAndCertsAreDeleted() {

	}

	void EnsureAttestationCertRemains() {

	}
}
