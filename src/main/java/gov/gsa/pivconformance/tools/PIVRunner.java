package gov.gsa.pivconformance.tools;

import gov.gsa.pivconformance.card.client.*;
import gov.gsa.pivconformance.tlv.*;
import gov.gsa.pivconformance.utils.PCSCUtils;
import gov.gsa.pivconformance.utils.VersionUtils;
import org.apache.commons.cli.*;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.text.SimpleDateFormat;

import javax.smartcardio.*;
import java.lang.invoke.MethodHandles;
import java.security.cert.X509Certificate;
import java.util.*;
import java.io.Console;


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


                result = MiddlewareStatus.PIV_AUTHENTICATION_FAILURE;
                //authenticators.addApplicationPin("123456");
//                Console cons = System.console();
//                char[] passwd;
//                if (cons != null && (passwd = cons.readPassword("[%s]", "Pin:")) != null) {
//
//                    PIVAuthenticators authenticators = new PIVAuthenticators();
//                    authenticators.addApplicationPin(new String(passwd));
//                    result = piv.pivLogIntoCardApplication(c, authenticators.getBytes());
//                    java.util.Arrays.fill(passwd, ' ');
//                }



                if(result != MiddlewareStatus.PIV_OK)
                    s_logger.error("Error authenticating to the smartcard: {}", result.toString());

                X509Certificate signingCertificate = null;

                for(String containerOID : APDUConstants.MandatoryContainers()) {
                    PIVDataObject dataObject = PIVDataObjectFactory.createDataObjectForOid(containerOID);
                    s_logger.info("Attempting to read data object for OID {} ({})", containerOID, APDUConstants.oidNameMAP.get(containerOID));
                    result = piv.pivGetData(c, containerOID, dataObject);
                    if(result != MiddlewareStatus.PIV_OK) continue;
                    boolean decoded = dataObject.decode();
                    s_logger.info("{} {}", dataObject.getFriendlyName(), decoded ? "decoded successfully" : "failed to decode");
                    s_logger.info("pivGetData returned {}", result);
                    s_logger.info(dataObject.toString());

                    if(containerOID.equals(APDUConstants.CARD_CAPABILITY_CONTAINER_OID)) {

                        s_logger.info("Card Identifier: {}", Hex.encodeHexString(((CardCapabilityContainer) dataObject).getCardIdentifier()));
                        s_logger.info("Capability Container Version Number: {}", Hex.encodeHexString(((CardCapabilityContainer) dataObject).getCapabilityContainerVersionNumber()));
                        s_logger.info("Capability Grammar Version Number: {}", Hex.encodeHexString(((CardCapabilityContainer) dataObject).getCapabilityGrammarVersionNumber()));

                        List<byte[]> appCardURLList = ((CardCapabilityContainer) dataObject).getAppCardURL();

                        if (appCardURLList.size() > 0) {
                            s_logger.info("Applications CardURL List");
                            for (byte[] u : appCardURLList) {
                                s_logger.info("{}", Hex.encodeHexString(u));
                            }
                        }


                        s_logger.info("Registered Data Model number: {}", Hex.encodeHexString(((CardCapabilityContainer) dataObject).getRegisteredDataModelNumber()));
                        s_logger.info("Access Control Rule Table: {}", Hex.encodeHexString(((CardCapabilityContainer) dataObject).getAccessControlRuleTable()));


                        s_logger.info("Card APDUs Tag Present: {}", ((CardCapabilityContainer) dataObject).getCardAPDUs());
                        s_logger.info("RedirectionTag Tag Present: {}", ((CardCapabilityContainer) dataObject).getRedirectionTag());
                        s_logger.info("Capability Tuples Tag Present: {}", ((CardCapabilityContainer) dataObject).getCapabilityTuples());
                        s_logger.info("Status Tuples Tag Present: {}", ((CardCapabilityContainer) dataObject).getStatusTuples());
                        s_logger.info("Next CCC Tag Present: {}", ((CardCapabilityContainer) dataObject).getNextCCC());

                        if (((CardCapabilityContainer) dataObject).getExtendedApplicationCardURL() != null) {

                            List<byte[]> extendedAppCardURLList = ((CardCapabilityContainer) dataObject).getExtendedApplicationCardURL();

                            if (extendedAppCardURLList.size() > 0) {
                                s_logger.info("Extended Application CardURL List:");
                                for (byte[] u2 : extendedAppCardURLList) {
                                    s_logger.info("     {}", Hex.encodeHexString(u2));
                                }
                            }
                        }

                        if (((CardCapabilityContainer) dataObject).getSecurityObjectBuffer() != null)
                            s_logger.info("Security Object Buffer: {}", Hex.encodeHexString(((CardCapabilityContainer) dataObject).getSecurityObjectBuffer()));


                        s_logger.info("Error Detection Code Tag Present: {}", ((CardCapabilityContainer) dataObject).getErrorDetectionCode());

                    }

                    if (containerOID.equals(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID)) {
                        if (((CardHolderUniqueIdentifier) dataObject).getBufferLength() != null) {
                            s_logger.info("Buffer Length: {}", Hex.encodeHexString(((CardHolderUniqueIdentifier) dataObject).getBufferLength()));
                        }
                        s_logger.info("FASC-N: {}", Hex.encodeHexString(((CardHolderUniqueIdentifier) dataObject).getfASCN()));
                        if (((CardHolderUniqueIdentifier) dataObject).getOrganizationalIdentifier() != null) {
                            s_logger.info("Organizational Identifier: {}", Hex.encodeHexString(((CardHolderUniqueIdentifier) dataObject).getOrganizationalIdentifier()));
                        }
                        if (((CardHolderUniqueIdentifier) dataObject).getdUNS() != null) {
                            s_logger.info("DUNS: {}", Hex.encodeHexString(((CardHolderUniqueIdentifier) dataObject).getdUNS()));
                        }
                        s_logger.info("GUID: {}", Hex.encodeHexString(((CardHolderUniqueIdentifier) dataObject).getgUID()));

                        SimpleDateFormat sdfmt = new SimpleDateFormat("MM/dd/yyyy");
                        s_logger.info("Expiration Date: {}", sdfmt.format(((CardHolderUniqueIdentifier) dataObject).getExpirationDate()));

                        s_logger.info("Cardholder UUID: {}", Hex.encodeHexString(((CardHolderUniqueIdentifier) dataObject).getCardholderUUID()));
                        s_logger.info("Issuer Asymmetric Signature Info:");

                        CMSSignedData sd = ((CardHolderUniqueIdentifier) dataObject).getIssuerAsymmetricSignature();
                        SignerInformationStore signers = sd.getSignerInfos();
                        Collection collection = signers.getSigners();
                        Iterator it = collection.iterator();

                        while (it.hasNext())
                        {
                            SignerInformation signer = (SignerInformation)it.next();
                            SignerId sid = signer.getSID();
                            String issuer = sid.getIssuer().toString();
                            String serial = Hex.encodeHexString(sid.getSerialNumber().toByteArray());
                            String skid = "";
                            if( sid.getSubjectKeyIdentifier() != null)
                                skid = Hex.encodeHexString(sid.getSubjectKeyIdentifier());

                            if(sid.getSubjectKeyIdentifier() != null)
                                s_logger.info("Signer skid: {} ", skid);
                            else
                                s_logger.info("Signer Issuer: {}, Serial Number: {} ", issuer, serial);

                        }
                        s_logger.info("Signature valid: {}", ((CardHolderUniqueIdentifier) dataObject).verifySignature());
                        signingCertificate = ((CardHolderUniqueIdentifier) dataObject).getSigningCertificate();

                        s_logger.info("Error Detection Code Tag Present: {}", ((CardHolderUniqueIdentifier) dataObject).getErrorDetectionCode());
                    }

                    if (containerOID.equals(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID)) {
                        X509Certificate pibAuthCert = ((X509CertificateDataObject) dataObject).getCertificate();

                        s_logger.info("PIV Auth Cert SubjectName: {}", pibAuthCert.getSubjectDN().getName());
                        s_logger.info("PIV Auth Cert SerialNumber: {}", Hex.encodeHexString(pibAuthCert.getSerialNumber().toByteArray()));
                        s_logger.info("PIV Auth Cert IssuerName: {}", pibAuthCert.getSubjectDN().getName());
                    }

                    if (containerOID.equals(APDUConstants.CARDHOLDER_FINGERPRINTS_OID)) {

                        s_logger.info("Fingerprint I & II: {}", Hex.encodeHexString(((CardholderBiometricData) dataObject).getBiometricData()));


                        s_logger.info("Biometric Creation Date: {}", ((CardholderBiometricData) dataObject).getBiometricCreationDate());
                        s_logger.info("Validity Period From: {}", ((CardholderBiometricData) dataObject).getValidityPeriodFrom());
                        s_logger.info("Validity Period To: {}",((CardholderBiometricData) dataObject).getValidityPeriodTo());


                        CMSSignedData sd = ((CardholderBiometricData) dataObject).getSignedData();
                        SignerInformationStore signers = sd.getSignerInfos();
                        Collection collection = signers.getSigners();
                        Iterator it = collection.iterator();

                        while (it.hasNext())
                        {
                            SignerInformation signer = (SignerInformation)it.next();
                            SignerId sid = signer.getSID();
                            String issuer = sid.getIssuer().toString();
                            String serial = Hex.encodeHexString(sid.getSerialNumber().toByteArray());
                            String skid = "";
                            if( sid.getSubjectKeyIdentifier() != null)
                                skid = Hex.encodeHexString(sid.getSubjectKeyIdentifier());

                            if(sid.getSubjectKeyIdentifier() != null)
                                s_logger.info("Signer skid: {} ", skid);
                            else
                                s_logger.info("Signer Issuer: {}, Serial Number: {} ", issuer, serial);

                        }
                        if(signingCertificate != null)
                            s_logger.info("Is signatue valid: {}",((CardholderBiometricData) dataObject).verifySignature(signingCertificate));
                        else
                            s_logger.info("Missing signing certificate to verify signature.");


                        s_logger.info("Error Detection Code Tag Present: {}", ((CardholderBiometricData) dataObject).getErrorDetectionCode());

                    }

                    if (containerOID.equals(APDUConstants.SECURITY_OBJECT_OID)) {


                        s_logger.info("RAW Mapping of DG to ContainerID value: {}", Hex.encodeHexString(((SecurityObject) dataObject).getMapping()));


                        List<String> cList = ((SecurityObject) dataObject).getContainerIDList();


                        s_logger.info("List of containers included in the Security Object:");
                        for(String oid : cList) {
                            s_logger.info(APDUConstants.oidNameMAP.get(oid));
                        }

                        CMSSignedData sd = ((SecurityObject) dataObject).getSignedData();
                        SignerInformationStore signers = sd.getSignerInfos();
                        Collection collection = signers.getSigners();
                        Iterator it = collection.iterator();

                        while (it.hasNext())
                        {
                            SignerInformation signer = (SignerInformation)it.next();
                            SignerId sid = signer.getSID();
                            String issuer = sid.getIssuer().toString();
                            String serial = Hex.encodeHexString(sid.getSerialNumber().toByteArray());
                            String skid = "";
                            if( sid.getSubjectKeyIdentifier() != null)
                                skid = Hex.encodeHexString(sid.getSubjectKeyIdentifier());

                            if(sid.getSubjectKeyIdentifier() != null)
                                s_logger.info("Signer skid: {} ", skid);
                            else
                                s_logger.info("Signer Issuer: {}, Serial Number: {} ", issuer, serial);

                        }
                        //s_logger.info("Error Detection Code Tag Present: {}", ((SecurityObject) dataObject).getErrorDetectionCode());
                    }

                    if (containerOID.equals(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID)) {
                        s_logger.info("Image for Visual Verification: {}", Hex.encodeHexString(((CardholderBiometricData) dataObject).getBiometricData()));

                        s_logger.info("Biometric Creation Date: {}", ((CardholderBiometricData) dataObject).getBiometricCreationDate());
                        s_logger.info("Validity Period From: {}", ((CardholderBiometricData) dataObject).getValidityPeriodFrom());
                        s_logger.info("Validity Period To: {}", ((CardholderBiometricData) dataObject).getValidityPeriodTo());


                        CMSSignedData sd = ((CardholderBiometricData) dataObject).getSignedData();
                        SignerInformationStore signers = sd.getSignerInfos();
                        Collection collection = signers.getSigners();
                        Iterator it = collection.iterator();

                        while (it.hasNext())
                        {
                            SignerInformation signer = (SignerInformation)it.next();
                            SignerId sid = signer.getSID();
                            String issuer = sid.getIssuer().toString();
                            String serial = Hex.encodeHexString(sid.getSerialNumber().toByteArray());
                            String skid = "";
                            if( sid.getSubjectKeyIdentifier() != null)
                                skid = Hex.encodeHexString(sid.getSubjectKeyIdentifier());

                            if(sid.getSubjectKeyIdentifier() != null)
                                s_logger.info("Signer skid: {} ", skid);
                            else
                                s_logger.info("Signer Issuer: {}, Serial Number: {} ", issuer, serial);

                        }

                        if(signingCertificate != null)
                            s_logger.info("Is signatue valid: {}",((CardholderBiometricData) dataObject).verifySignature(signingCertificate));
                        else
                            s_logger.info("Missing signing certificate to verify signature.");

                        s_logger.info("Error Detection Code Tag Present: {}", ((CardholderBiometricData) dataObject).getErrorDetectionCode());
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

                PIVDataObject printedInformation = PIVDataObjectFactory.createDataObjectForOid(APDUConstants.PRINTED_INFORMATION_OID);
                result = piv.pivGetData(c, APDUConstants.PRINTED_INFORMATION_OID, printedInformation);

                if(result == MiddlewareStatus.PIV_OK) {
                    s_logger.info("Attempted to read {} object: {}", APDUConstants.oidNameMAP.get(APDUConstants.PRINTED_INFORMATION_OID), result);
                    boolean decoded = printedInformation.decode();
                    s_logger.info("{} {}", printedInformation.getFriendlyName(), decoded ? "decoded successfully" : "failed to decode");

                    if (decoded) {
                        s_logger.info("Name: {}", ((PrintedInformation) printedInformation).getName());
                        s_logger.info("Employee Affiliation: {}", ((PrintedInformation) printedInformation).getEmployeeAffiliation());
                        s_logger.info("Expiration date: {}", ((PrintedInformation) printedInformation).getExpirationDate());
                        s_logger.info("Agency Card Serial Number: {}", ((PrintedInformation) printedInformation).getAgencyCardSerialNumber());
                        s_logger.info("Issuer Identification: {}", ((PrintedInformation) printedInformation).getIssuerIdentification());
                        if (((PrintedInformation) printedInformation).getOrganizationAffiliation1() != "")
                            s_logger.info("Name: {}", ((PrintedInformation) printedInformation).getOrganizationAffiliation1());
                        if (((PrintedInformation) printedInformation).getOrganizationAffiliation2() != "")
                            s_logger.info("Name: {}", ((PrintedInformation) printedInformation).getOrganizationAffiliation2());
                        s_logger.info("Error Detection Code Tag Present: {}", ((PrintedInformation) printedInformation).getErrorDetectionCode());

                    }
                }

                boolean decoded = false;
                PIVDataObject discoveryObject = PIVDataObjectFactory.createDataObjectForOid(APDUConstants.DISCOVERY_OBJECT_OID);
                result = piv.pivGetData(c, APDUConstants.DISCOVERY_OBJECT_OID, discoveryObject);

                if(result == MiddlewareStatus.PIV_OK) {
                    s_logger.info("Attempted to read discovery object: {}", result);
                    decoded = discoveryObject.decode();
                    s_logger.info("{} {}", discoveryObject.getFriendlyName(), decoded ? "decoded successfully" : "failed to decode");
                }




                PIVDataObject cardholderIrisImages = PIVDataObjectFactory.createDataObjectForOid(APDUConstants.CARDHOLDER_IRIS_IMAGES_OID);
                result = piv.pivGetData(c, APDUConstants.CARDHOLDER_IRIS_IMAGES_OID, cardholderIrisImages);

                if(result == MiddlewareStatus.PIV_OK) {
                    s_logger.info("Attempted to read {} object: {}", APDUConstants.oidNameMAP.get(APDUConstants.CARDHOLDER_IRIS_IMAGES_OID), result);
                    decoded = cardholderIrisImages.decode();
                    s_logger.info("{} {}", cardholderIrisImages.getFriendlyName(), decoded ? "decoded successfully" : "failed to decode");

                    if (decoded) {
                        if (((CardholderBiometricData) cardholderIrisImages).getBiometricData() != null) {
                            s_logger.info("Images for Iris: {}", Hex.encodeHexString(((CardholderBiometricData) cardholderIrisImages).getBiometricData()));

                            s_logger.info("Biometric Creation Date: {}", ((CardholderBiometricData) cardholderIrisImages).getBiometricCreationDate());
                            s_logger.info("Validity Period From: {}", ((CardholderBiometricData) cardholderIrisImages).getValidityPeriodFrom());
                            s_logger.info("Validity Period To: {}", ((CardholderBiometricData) cardholderIrisImages).getValidityPeriodTo());


                            CMSSignedData sd = ((CardholderBiometricData) cardholderIrisImages).getSignedData();
                            SignerInformationStore signers = sd.getSignerInfos();
                            Collection collection = signers.getSigners();
                            Iterator it = collection.iterator();

                            while (it.hasNext())
                            {
                                SignerInformation signer = (SignerInformation)it.next();
                                SignerId sid = signer.getSID();
                                String issuer = sid.getIssuer().toString();
                                String serial = Hex.encodeHexString(sid.getSerialNumber().toByteArray());
                                String skid = "";
                                if( sid.getSubjectKeyIdentifier() != null)
                                    skid = Hex.encodeHexString(sid.getSubjectKeyIdentifier());

                                if(sid.getSubjectKeyIdentifier() != null)
                                    s_logger.info("Signer skid: {} ", skid);
                                else
                                    s_logger.info("Signer Issuer: {}, Serial Number: {} ", issuer, serial);

                            }

                            if(signingCertificate != null)
                                s_logger.info("Is signatue valid: {}",((CardholderBiometricData) cardholderIrisImages).verifySignature(signingCertificate));
                            else
                                s_logger.info("Missing signing certificate to verify signature.");
                        }
                        s_logger.info("Error Detection Code Tag Present: {}", ((CardholderBiometricData) cardholderIrisImages).getErrorDetectionCode());

                    }
                }

                PIVDataObject keyHistoryObject = PIVDataObjectFactory.createDataObjectForOid(APDUConstants.KEY_HISTORY_OBJECT_OID);
                result = piv.pivGetData(c, APDUConstants.KEY_HISTORY_OBJECT_OID, keyHistoryObject);

                if(result == MiddlewareStatus.PIV_OK) {
                    s_logger.info("Attempted to read key history object: {}", result);
                    decoded = keyHistoryObject.decode();
                    if (decoded) {
                        s_logger.info("Decoded successfully {}", keyHistoryObject.toString());
                    }
                }


                PIVDataObject biometricInformationTemplatesGroupTemplate = PIVDataObjectFactory.createDataObjectForOid(APDUConstants.BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID);
                result = piv.pivGetData(c, APDUConstants.BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID, biometricInformationTemplatesGroupTemplate);

                if(result == MiddlewareStatus.PIV_OK) {
                    s_logger.info("Attempted to read {} object: {}", APDUConstants.oidNameMAP.get(APDUConstants.BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID), result);
                    decoded = biometricInformationTemplatesGroupTemplate.decode();
                    s_logger.info("{} {}", biometricInformationTemplatesGroupTemplate.getFriendlyName(), decoded ? "decoded successfully" : "failed to decode");

                    if (decoded) {

                        s_logger.info("Number of fingers: {}", ((BiometricInformationTemplatesGroupTemplate) biometricInformationTemplatesGroupTemplate).getNumberOfFingers());
                        if (((BiometricInformationTemplatesGroupTemplate) biometricInformationTemplatesGroupTemplate).getbITForFirstFinger() != null)
                            s_logger.info("BIT for first Finger: {}", Hex.encodeHexString(((BiometricInformationTemplatesGroupTemplate) biometricInformationTemplatesGroupTemplate).getbITForFirstFinger()));
                        if (((BiometricInformationTemplatesGroupTemplate) biometricInformationTemplatesGroupTemplate).getbITForSecondFinger() != null)
                            s_logger.info("BIT for second Finger: {}", Hex.encodeHexString(((BiometricInformationTemplatesGroupTemplate) biometricInformationTemplatesGroupTemplate).getbITForSecondFinger()));

                    }
                }


                PIVDataObject secureMessagingCertificateSigner = PIVDataObjectFactory.createDataObjectForOid(APDUConstants.SECURE_MESSAGING_CERTIFICATE_SIGNER_OID);
                result = piv.pivGetData(c, APDUConstants.SECURE_MESSAGING_CERTIFICATE_SIGNER_OID, secureMessagingCertificateSigner);

                if(result == MiddlewareStatus.PIV_OK) {
                    s_logger.info("Attempted to read {} object: {}", APDUConstants.oidNameMAP.get(APDUConstants.SECURE_MESSAGING_CERTIFICATE_SIGNER_OID), result);
                    decoded = secureMessagingCertificateSigner.decode();
                    s_logger.info("{} {}", secureMessagingCertificateSigner.getFriendlyName(), decoded ? "decoded successfully" : "failed to decode");

                    if (decoded) {

                        X509Certificate contentSigningCert = ((SecureMessagingCertificateSigner) secureMessagingCertificateSigner).getCertificate();

                        s_logger.info("Content Signing Cert SubjectName: {}", contentSigningCert.getSubjectDN().getName());
                        s_logger.info("Content Signing Cert SerialNumber: {}", Hex.encodeHexString(contentSigningCert.getSerialNumber().toByteArray()));
                        s_logger.info("Content Signing Cert IssuerName: {}", contentSigningCert.getSubjectDN().getName());

                        if (((SecureMessagingCertificateSigner) secureMessagingCertificateSigner).getIntermediateCVC() != null)
                            s_logger.info("Intermediate CVC: {}", Hex.encodeHexString(((SecureMessagingCertificateSigner) secureMessagingCertificateSigner).getIntermediateCVC()));

                    }
                }

                PIVDataObject pairingCodeReferenceDataContainer = PIVDataObjectFactory.createDataObjectForOid(APDUConstants.PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID);
                result = piv.pivGetData(c, APDUConstants.PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID, pairingCodeReferenceDataContainer);

                if(result == MiddlewareStatus.PIV_OK) {
                    s_logger.info("Attempted to read {} object: {}", APDUConstants.oidNameMAP.get(APDUConstants.PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID), result);
                    decoded = pairingCodeReferenceDataContainer.decode();
                    s_logger.info("{} {}", pairingCodeReferenceDataContainer.getFriendlyName(), decoded ? "decoded successfully" : "failed to decode");

                    if (decoded) {
                        s_logger.info("Name: {}", ((PairingCodeReferenceDataContainer) pairingCodeReferenceDataContainer).getName());
                        s_logger.info("Error Detection Code Tag Present: {}", ((PairingCodeReferenceDataContainer) pairingCodeReferenceDataContainer).getErrorDetectionCode());

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
