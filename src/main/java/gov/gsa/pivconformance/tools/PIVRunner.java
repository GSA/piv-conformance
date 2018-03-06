package gov.gsa.pivconformance.tools;

import gov.gsa.pivconformance.card.client.*;
import gov.gsa.pivconformance.tlv.*;
import gov.gsa.pivconformance.utils.PCSCUtils;
import gov.gsa.pivconformance.utils.VersionUtils;
import org.apache.commons.cli.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.text.SimpleDateFormat;

import javax.smartcardio.*;
import java.lang.invoke.MethodHandles;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

public class PIVRunner {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(PIVRunner.class);
    private static final Options s_options = new Options();

    static {
        s_options.addOption("a", "all", false, "Scan all readers");
        s_options.addOption("h", "help", false, "Print this help and exit");
    }

    private static void PrintHelpAndExit(int exitCode) {
        new HelpFormatter().printHelp("PIVRunner <options>", s_options);
        System.exit(exitCode);
    }

    public static boolean TestCard(CardHandle c) {
        if(c.isValid()) {
            CardTerminal t = c.getConnectionDescription().getTerminal();
            try {
                if(t.isCardPresent()) {
                    s_logger.info("Card found in reader {}", t.getName());
                } else {
                    s_logger.error("No card was present in reader {}", t.getName());
                    return false;
                }
            } catch (CardException e) {
                s_logger.error("Card communication error", e);
            }
            Card conn = c.getCard();
            s_logger.info("Card connected.");
            s_logger.info("Card protocol: {}", conn.getProtocol());
            s_logger.info("Card ATR: {}", Hex.encodeHexString(conn.getATR().getBytes()));
            ApplicationProperties cardAppProperties = new ApplicationProperties();
            DefaultPIVApplication piv = new DefaultPIVApplication();
            ApplicationAID aid = new ApplicationAID();
            s_logger.info("Attempting to select default PIV application");
            MiddlewareStatus result = piv.pivSelectCardApplication(c, aid, cardAppProperties);
            s_logger.info("pivSelectCardApplication() returned {}", result);
            if(result == MiddlewareStatus.PIV_OK) {
                byte[] pcap = cardAppProperties.getBytes();

                byte [] appID = cardAppProperties.getAppID();
                String appLabel = cardAppProperties.getAppLabel();
                String url = cardAppProperties.getURL();
                List<byte[]> cryptoAlgs = cardAppProperties.getCryptoAlgs();
                byte [] coexistentTagAllocationAuthority = cardAppProperties.getCoexistentTagAllocationAuthority();

                if(appID != null)
                    s_logger.info("Application identifier of application: {}", Hex.encodeHexString(appID));

                if(coexistentTagAllocationAuthority != null)
                    s_logger.info("Coexistent tag allocation authority: {}", Hex.encodeHexString(coexistentTagAllocationAuthority));

                if(appLabel != "")
                    s_logger.info("Application label: {}", appLabel);

                if(url != "")
                    s_logger.info("Uniform resource locator: {}", url);

                if(cryptoAlgs != null) {
                    for(byte[] b : cryptoAlgs) {

                        s_logger.info("Cryptographic algorithms supported:");
                        s_logger.info("Algorithm ID: {} Algorithm Description: {}", Hex.encodeHexString(b), TagConstants.algMAP.get(b));
                    }
                }


                s_logger.info("PCAP: {}", Hex.encodeHexString(pcap));
                BerTlvParser tp = new BerTlvParser(new CCTTlvLogger(PIVRunner.class));
                BerTlv outer = tp.parseConstructed(pcap);
                List<BerTlv> values = outer.getValues();
                for(BerTlv tlv : values) {
                    if(tlv.isPrimitive()) {
                        s_logger.info("PCAP Tag {}: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));
                    } else {
                        s_logger.info("PCAP object: {}", Hex.encodeHexString(tlv.getTag().bytes));
                    }
                }
                PIVDataObject discoveryObject = PIVDataObjectFactory.createDataObjectForOid(APDUConstants.DISCOVERY_OBJECT_OID);
                result = piv.pivGetData(c, APDUConstants.DISCOVERY_OBJECT_OID, discoveryObject);
                s_logger.info("Attempted to read discovery object: {}", result);
                boolean decoded = discoveryObject.decode();
                s_logger.info("{} {}", discoveryObject.getFriendlyName(), decoded ? "decoded successfully" : "failed to decode");
                for(String containerOID : APDUConstants.MandatoryContainers()) {
                    PIVDataObject dataObject = PIVDataObjectFactory.createDataObjectForOid(containerOID);
                    s_logger.info("Attempting to read data object for OID {} ({})", containerOID, APDUConstants.oidNameMAP.get(containerOID));
                    result = piv.pivGetData(c, containerOID, dataObject);
                    decoded = dataObject.decode();
                    s_logger.info("{} {}", dataObject.getFriendlyName(), decoded ? "decoded successfully" : "failed to decode");
                    s_logger.info("pivGetData returned {}", result);
                    if(result != MiddlewareStatus.PIV_OK) continue;
                    s_logger.info(dataObject.toString());

                    if(containerOID.equals(APDUConstants.CARD_CAPABILITY_CONTAINER_OID)){

                        s_logger.info("Card Identifier: {}", Hex.encodeHexString(((CardCapabilityContainer) dataObject).getCardIdentifier()));
                        s_logger.info("Capability Container Version Number: {}", Hex.encodeHexString(((CardCapabilityContainer) dataObject).getCapabilityContainerVersionNumber()));
                        s_logger.info("Capability Grammar Version Number: {}", Hex.encodeHexString(((CardCapabilityContainer) dataObject).getCapabilityGrammarVersionNumber()));

                        List<byte[]> appCardURLList = ((CardCapabilityContainer) dataObject).getAppCardURL();

                        if(appCardURLList.size() > 0) {
                            s_logger.info("Applications CardURL List");
                            for(byte[] u : appCardURLList) {
                                s_logger.info("{}", Hex.encodeHexString(u));
                            }
                        }


                        s_logger.info("Registered Data Model number: {}", Hex.encodeHexString(((CardCapabilityContainer) dataObject).getRegisteredDataModelNumber()));
                        s_logger.info("Access Control Rule Table: {}", Hex.encodeHexString(((CardCapabilityContainer) dataObject).getAccessControlRuleTable()));


                        s_logger.info("Card APDUs Tag Preset: {}", ((CardCapabilityContainer) dataObject).getCardAPDUs());
                        s_logger.info("RedirectionTag Tag Preset: {}", ((CardCapabilityContainer) dataObject).getRedirectionTag());
                        s_logger.info("Capability Tuples Tag Preset: {}", ((CardCapabilityContainer) dataObject).getCapabilityTuples());
                        s_logger.info("Status Tuples Tag Preset: {}", ((CardCapabilityContainer) dataObject).getStatusTuples());
                        s_logger.info("Next CCC Tag Preset: {}", ((CardCapabilityContainer) dataObject).getNextCCC());

                        if(((CardCapabilityContainer) dataObject).getExtendedApplicationCardURL() != null) {

                            List<byte[]> extendedAppCardURLList = ((CardCapabilityContainer) dataObject).getExtendedApplicationCardURL();

                            if(extendedAppCardURLList.size() > 0) {
                                s_logger.info("Extended Application CardURL List:");
                                for(byte[] u2 : extendedAppCardURLList) {
                                    s_logger.info("     {}", Hex.encodeHexString(u2));
                                }
                            }
                        }

                        if(((CardCapabilityContainer) dataObject).getSecurityObjectBuffer() != null)
                            s_logger.info("Security Object Buffer: {}", Hex.encodeHexString(((CardCapabilityContainer) dataObject).getSecurityObjectBuffer()));


                        s_logger.info("Error Detection Code Tag Preset: {}", ((CardCapabilityContainer) dataObject).getErrorDetectionCode());
                    }
                    if(containerOID.equals(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID)){
                        if(((CardHolderUniqueIdentifier) dataObject).getBufferLength() != null) {
                            s_logger.info("Buffer Length: {}", Hex.encodeHexString(((CardHolderUniqueIdentifier) dataObject).getBufferLength()));
                        }
                        s_logger.info("FASC-N: {}", Hex.encodeHexString(((CardHolderUniqueIdentifier) dataObject).getfASCN()));
                        if(((CardHolderUniqueIdentifier) dataObject).getOrganizationalIdentifier() != null) {
                            s_logger.info("Organizational Identifier: {}", Hex.encodeHexString(((CardHolderUniqueIdentifier) dataObject).getOrganizationalIdentifier()));
                        }
                        if(((CardHolderUniqueIdentifier) dataObject).getdUNS() != null) {
                            s_logger.info("DUNS: {}", Hex.encodeHexString(((CardHolderUniqueIdentifier) dataObject).getdUNS()));
                        }
                        s_logger.info("GUID: {}", Hex.encodeHexString(((CardHolderUniqueIdentifier) dataObject).getgUID()));

                        SimpleDateFormat sdfmt = new SimpleDateFormat("MM/dd/yyyy");
                        s_logger.info("Expiration Date: {}", sdfmt.format(((CardHolderUniqueIdentifier) dataObject).getExpirationDate()));

                        s_logger.info("Cardholder UUID: {}", Hex.encodeHexString(((CardHolderUniqueIdentifier) dataObject).getCardholderUUID()));
                        s_logger.info("Issuer Asymmetric Signature: {}", Hex.encodeHexString(((CardHolderUniqueIdentifier) dataObject).getIssuerAsymmetricSignature()));
                        s_logger.info("Error Detection Code Tag Preset: {}", ((CardHolderUniqueIdentifier) dataObject).getErrorDetectionCode());
                    }

                    if(containerOID.equals(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID)){
                        X509Certificate pibAuthCert = ((X509CertificateDataObject) dataObject).getCertificate();

                        s_logger.info("PIV Auth Cert SubjectName: {}", pibAuthCert.getSubjectDN().getName());
                        s_logger.info("PIV Auth Cert SerialNumber: {}", Hex.encodeHexString(pibAuthCert.getSerialNumber().toByteArray()));
                        s_logger.info("PIV Auth Cert IssuerName: {}", pibAuthCert.getSubjectDN().getName());
                    }

                    if(containerOID.equals(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID)){
                        X509Certificate pibAuthCert = ((X509CertificateDataObject) dataObject).getCertificate();

                        s_logger.info("Key Managment Cert SubjectName: {}", pibAuthCert.getSubjectDN().getName());
                        s_logger.info("Key Managment Cert SerialNumber: {}", Hex.encodeHexString(pibAuthCert.getSerialNumber().toByteArray()));
                        s_logger.info("Key Managment Cert IssuerName: {}", pibAuthCert.getSubjectDN().getName());
                    }

                    if(containerOID.equals(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID)){
                        X509Certificate pibAuthCert = ((X509CertificateDataObject) dataObject).getCertificate();

                        s_logger.info("Digital Signature Cert SubjectName: {}", pibAuthCert.getSubjectDN().getName());
                        s_logger.info("Digital Signature SerialNumber: {}", Hex.encodeHexString(pibAuthCert.getSerialNumber().toByteArray()));
                        s_logger.info("Digital Signature IssuerName: {}", pibAuthCert.getSubjectDN().getName());
                    }

                    if(containerOID.equals(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID)){
                        X509Certificate pibAuthCert = ((X509CertificateDataObject) dataObject).getCertificate();

                        s_logger.info("Card Auth Cert SubjectName: {}", pibAuthCert.getSubjectDN().getName());
                        s_logger.info("Card Auth Cert SerialNumber: {}", Hex.encodeHexString(pibAuthCert.getSerialNumber().toByteArray()));
                        s_logger.info("Card Auth Cert IssuerName: {}", pibAuthCert.getSubjectDN().getName());
                    }
                }

            }
            ResponseAPDU rsp = null;
            return true;
        } else {
            s_logger.error("TestCard called with invalid card handle");
        }
        return false;
    }

    public static void main(String[] args) {
        s_logger.info("main class: {}", MethodHandles.lookup().lookupClass().getSimpleName());
        s_logger.info("package version: {}", VersionUtils.GetPackageVersionString());
        s_logger.info("build time: {}", VersionUtils.GetPackageBuildTime());

        CommandLineParser p = new DefaultParser();
        CommandLine cmd = null;
        try {
            cmd = p.parse(s_options, args);
        } catch (ParseException e) {
            s_logger.error("Failed to parse command line arguments", e);
            PrintHelpAndExit(1);
        }

        if(cmd.hasOption("help")) {
            PrintHelpAndExit(0);
        }

        PCSCUtils.ConfigureUserProperties();
        PIVMiddlewareVersion mwv = new PIVMiddlewareVersion();
        MiddlewareStatus middlewareStatus = PIVMiddleware.pivMiddlewareVersion(mwv);
        s_logger.info("pivMiddlewareVersion returned status {} and version {}", middlewareStatus, mwv);

        TerminalFactory tf = TerminalFactory.getDefault();
        List<CardTerminal> terminals = null;
        try {
            terminals = tf.terminals().list();
        } catch (CardException e) {
            s_logger.error("Failed to list card terminals", e);
            System.exit(1);
        }
        if(terminals.size() == 0) {
            s_logger.error("No readers were found.");
            System.exit(1);
        }
        int terminalCount = 0;
        for(CardTerminal t : terminals) {
            terminalCount++;
            ConnectionDescription cd = ConnectionDescription.createFromTerminal(t);
            byte[] descriptor = cd.getBytes();
            if(descriptor != null) {
                s_logger.info("Descriptor for terminal {}: {}", terminalCount, Hex.encodeHexString(descriptor, false));
            }
            // if there is only one reader or if we've been asked to only test one reader,
            // wait for a card
            try {
                if(!t.isCardPresent() && (!cmd.hasOption("all") || terminals.size() == 1)) {
                    s_logger.info("Insert a card into {}", t.getName());
                    t.waitForCardPresent(0);
                }
            } catch (CardException e) {
                s_logger.error("Error checking for card presence", e);
            }
            s_logger.info("Testing with terminal {}: {}", terminalCount, t.getName());
            CardHandle ch = new CardHandle();
            MiddlewareStatus result = PIVMiddleware.pivConnect(true, cd, ch);
            s_logger.info("[{}] PIVMiddleware.pivConnect() returned {} for reader {}", terminalCount, result, t.getName());
            boolean testResult = TestCard(ch);
            if(testResult) {
                s_logger.info("Card test completed successfully.");
            } else {
                s_logger.error("Card test failed.");
            }
            if(!cmd.hasOption("all")) {
                break;
            }
        }

        System.exit(0);

    }
}
