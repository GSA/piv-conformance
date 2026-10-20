package gov.gsa.pivconformance.gui;

import gov.gsa.pivconformance.cardlib.card.client.CardHandle;
import gov.gsa.pivconformance.conformancelib.configuration.CardSettingsSingleton;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.smartcardio.ATR;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class ReaderAndVersionRegressionTest {
    @Test
    void changingReaderReleasesTheOldConnection() {
        CardSettingsSingleton settings = CardSettingsSingleton.getInstance();
        settings.reset();
        AtomicInteger disconnects = new AtomicInteger();
        Card previous = new Card() {
            @Override public ATR getATR() { return null; }
            @Override public String getProtocol() { return "T=1"; }
            @Override public CardChannel getBasicChannel() { return null; }
            @Override public CardChannel openLogicalChannel() throws CardException { return null; }
            @Override public void beginExclusive() throws CardException { }
            @Override public void endExclusive() throws CardException { }
            @Override public byte[] transmitControlCommand(int controlCode, byte[] command) throws CardException { return null; }
            @Override public void disconnect(boolean reset) { disconnects.incrementAndGet(); }
        };
        CardHandle handle = new CardHandle();
        handle.setCard(previous);
        handle.setValid(true);
        settings.setCardHandle(handle);
        settings.setReaderIndex(1);

        SimpleTestExecutionPanel.resetCardSession(settings);

        assertEquals(1, disconnects.get());
        assertNull(settings.getCardHandle());
        assertEquals(-1, settings.getReaderIndex());
    }

    @Test
    void versionComesFromBundledResourceDespiteStaleLocalFile(@TempDir Path directory) throws Exception {
        Files.writeString(directory.resolve("build.version"), "1.0.7\n");
        String bundledVersion;
        try (InputStream resource = GuiRunnerApplication.class.getResourceAsStream("/build.version")) {
            bundledVersion = new String(resource.readAllBytes()).trim();
        }
        String previousDirectory = System.getProperty("user.dir");
        try {
            System.setProperty("user.dir", directory.toString());
            assertEquals(bundledVersion, GuiRunnerApplication.getVersion("build.version"));
        } finally {
            System.setProperty("user.dir", previousDirectory);
        }
    }
}
