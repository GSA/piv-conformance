package gov.gsa.pivconformance.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsSource;

import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObject;
import gov.gsa.pivconformance.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.pivconformance.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.cardlib.tlv.BerTlvParser;
import gov.gsa.pivconformance.cardlib.tlv.CCTTlvLogger;

public class BER_TLVTests {
	
	//Length field encoded as shown in SP800-85B Table 1
    @DisplayName("BERTLV.1 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("bertlvTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void berTLV_Test_1(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
        	
        byte[] bertlv = o.getBytes();
        assertNotNull(bertlv);
        
        BerTlvParser tp = new BerTlvParser(new CCTTlvLogger(BER_TLVTests.class));
        
    	int aOffset = 0;
    	// tag
        int tagBytesCount = tp.getTagBytesCount(bertlv, aOffset);
        
        
        // length
        int lengthBytesCount  = BerTlvParser.getLengthBytesCount(bertlv, aOffset + tagBytesCount);
        int valueLength       = tp.getDataLength(bertlv, aOffset + tagBytesCount);
        
        
        Byte firstByte = bertlv[aOffset + tagBytesCount];
        
        if(lengthBytesCount == 1) {
        	//If length is 1 byte first between '00' and '7F'
        	
        	int l = firstByte.intValue();        	
        	assertTrue(l > 0);
        	assertTrue(l <= 127);
        	
        	assertTrue(valueLength > 0);
        	assertTrue(valueLength <= 127);
        	
        }else if(lengthBytesCount == 2) {
        	
        	//If length is 2 bytes first byte is '81'
        	assertTrue((firstByte & 0x81) == 0x81);
        	
        	assertTrue(valueLength > 0);
        	assertTrue(valueLength <= 255);
        	
        }else if(lengthBytesCount == 3) {
        	
        	//If length is 3 bytes first byte is '82'
        	assertTrue((firstByte & 0x82)  == 0x82);
        	
        	assertTrue(valueLength > 0);
        	assertTrue(valueLength <= 65535);
        	
        }else if(lengthBytesCount == 4) {
        	
        	//If length is 4 bytes first byte is '83'
        	assertTrue((firstByte & 0x83) == 0x83);
        	
        	assertTrue(valueLength > 0);
        	assertTrue(valueLength <= 16777215);
        	
        }else if(lengthBytesCount == 5) {
        	
        	//If length is 5 bytes first byte is '84'
        	assertTrue((firstByte & 0x85) == 0x85);
        	
        	assertTrue(valueLength > 0);
        	
        	byte[] restLengthBytes = Arrays.copyOfRange(bertlv, aOffset + tagBytesCount + 1, lengthBytesCount);
        	
        	BigInteger lenValue = new BigInteger(restLengthBytes);
        	BigInteger f = new BigInteger("4294967295");
        	assertTrue(lenValue.compareTo(f) != 1);
        }
    }
    
    //Tag encoded as 3 bytes
    @DisplayName("BERTLV.2 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("bertlvTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void berTLV_Test_2(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);

        byte[] bertlv = o.getBytes();
        
        // pivGetData retrieves each data container using the 3 byte tag checking for a successful return code and returned bytes should satisfy this test
        // TODO: Confirm that this assumption is correct
        assertNotNull(bertlv);
    }
    
    //Each data object returned with 2 byte status word (90 00)
    @DisplayName("BERTLV.3 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("bertlvTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void berTLV_Test_3(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
        byte[] bertlv = o.getBytes();           
        assertNotNull(bertlv);
    }
    
    //If a variable length field has length of 0, tag length is followed immediately by next tag if applicable
    @DisplayName("BERTLV.4 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("bertlvTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void berTLV_Test_4(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);

        byte[] bertlv = o.getBytes();
        assertNotNull(bertlv);
        
        // Our TLV parser would have thrown if a variable length field had a 0 length but was followed by something other than
        // a next tag. non-null getBytes() should pass this atom.
    }
    
    //Setting final byte of command string to 0x00 retrieves entire data object regardless of size
    @DisplayName("BERTLV.5 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("bertlvTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void berTLV_Test_5(String oid, TestReporter reporter) {

    	PIVDataObject o = AtomHelper.getDataObject(oid);
        
        boolean decoded = o.decode();
        
        // if the object decoded successfully, this test passed.
        // Confirm that we received all the data for the object and are able to decode.
        assertTrue(decoded);

    }
    
    /* only use to test mods to the atoms... no longer needed now that containers are in the database */
    @SuppressWarnings("unused")
	private static Stream<Arguments> bertlvTestProvider() {
    	
    	return Stream.of(
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID),
                Arguments.of(APDUConstants.SECURITY_OBJECT_OID),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID),
                Arguments.of(APDUConstants.DISCOVERY_OBJECT_OID)
                //Arguments.of(APDUConstants.KEY_HISTORY_OBJECT_OID),
                //Arguments.of(APDUConstants.CARDHOLDER_IRIS_IMAGES_OID),
                //Arguments.of(APDUConstants.BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID)
                //Arguments.of(APDUConstants.SECURE_MESSAGING_CERTIFICATE_SIGNER_OID),
                //Arguments.of(APDUConstants.PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID)
                );

    }
}
