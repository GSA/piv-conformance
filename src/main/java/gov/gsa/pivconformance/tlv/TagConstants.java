package gov.gsa.pivconformance.tlv;

import java.util.HashMap;

public class TagConstants {
    public static final byte[] AID_TAG = { 0x4F };
    public static final byte[] APPLICATION_LABEL = { 0x50 };
    public static final byte[] UNIFORM_RESOURCE_LOCATOR = { 0x50 };
    public static final byte[] CRYPTOGRAPHIC_ALGORITHMS = { (byte) 0xAC };
    public static final byte[] CRYPTOGRAPHIC_ALGORITHM_IDENTIFIER = { (byte) 0x80 };
    public static final byte[] OBJECT_IDENTIFIER = { (byte) 0x06 };
    public static final byte[] TAG_LIST = { 0x5c };
    public static final byte[] COEXISTENT_TAG_ALLOCATION_AUTHORITY = { 0x79 };

    public static final byte[] Three_Key_Triple_DES_ECB_ID =  { 0x00 };
    public static final String Three_Key_Triple_DES_ECB = "3 Key Triple DES – ECB";

    public static final byte[] Three_Key_Triple_DES_ECB2_ID =  { 0x03 };
    public static final String Three_Key_Triple_DES_ECB2 = "3 Key Triple DES – ECB";

    public static final byte[] RSA_1024_bit_ID =  { 0x06 };
    public static final String RSA_1024_bit = "RSA 1024 bit modulus, 65 537 ≤ exponent ≤ 2256 - 1";

    public static final byte[] RSA_2048_bit_ID =  { 0x07 };
    public static final String RSA_2048_bit = "RSA 2048 bit modulus, 65 537 ≤ exponent ≤ 2256 - 1";

    public static final byte[] AES_128_ID =  { 0x08 };
    public static final String AES_128 = "AES-128 – ECB";

    public static final byte[] AES_192_ID =  { 0x0A };
    public static final String AES_192 = "AES-192 – ECB";

    public static final byte[] AES_256_ID =  { 0x0C };
    public static final String AES_256 = "AES-256 – ECB";

    public static final byte[] ECC_Curve_P_256_ID =  { 0x11 };
    public static final String ECC_Curve_P_256 = "ECC: Curve P-256";

    public static final byte[] ECC_Curve_P_384_ID =  { 0x14 };
    public static final String ECC_Curve_P_384 = "ECC: Curve P-384";

    public static final byte[] Cipher_Suite_2_ID =  { 0x27 };
    public static final String Cipher_Suite_2 = "Cipher Suite 2";

    public static final byte[] Cipher_Suite_7_ID =  { 0x2E };
    public static final String Cipher_Suite_7 = "Cipher Suite 7";

    public static final HashMap<byte[], String> algMAP = new HashMap<byte[], String>(){
        {
            put(Three_Key_Triple_DES_ECB_ID, Three_Key_Triple_DES_ECB);
            put(Three_Key_Triple_DES_ECB2_ID, Three_Key_Triple_DES_ECB2);
            put(RSA_1024_bit_ID, RSA_1024_bit);
            put(RSA_2048_bit_ID, RSA_2048_bit);
            put(AES_128_ID, AES_128);
            put(AES_192_ID, AES_192);
            put(AES_256_ID, AES_256);
            put(ECC_Curve_P_256_ID, ECC_Curve_P_256);
            put(ECC_Curve_P_384_ID, ECC_Curve_P_384);
            put(Cipher_Suite_2_ID, Cipher_Suite_2);
            put(Cipher_Suite_7_ID, Cipher_Suite_7);
        }
    };
}
