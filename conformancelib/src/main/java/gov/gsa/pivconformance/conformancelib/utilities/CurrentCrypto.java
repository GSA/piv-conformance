package gov.gsa.pivconformance.conformancelib.utilities;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Set;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import static gov.gsa.pivconformance.conformancelib.utilities.CurrentDataModel.require;

/** SP 800-78-5 candidate: active card keys, through-2030 column only.
 * Does not evaluate retired keys, issuer keys, CMVP, key generation, or signature validity.
 */
public final class CurrentCrypto {
    private CurrentCrypto() { }
    public static final String RSA = "1.2.840.113549.1.1.1";
    public static final String EC = "1.2.840.10045.2.1";
    public static final String P256 = "1.2.840.10045.3.1.7";
    public static final String P384 = "1.3.132.0.34";
    public static final String SHA256 = "2.16.840.1.101.3.4.2.1";
    public static final String SHA384 = "2.16.840.1.101.3.4.2.2";
    public static final String PSS = "1.2.840.113549.1.1.10";

    private static ASN1Primitive der(byte[] value, String rule) {
        try {
            require(value != null, rule, "missing DER value");
            ASN1Primitive parsed = ASN1Primitive.fromByteArray(value);
            require(Arrays.equals(value, parsed.getEncoded(ASN1Encoding.DER)),rule,"non-DER encoding");
            return parsed;
        } catch (Exception e) { throw new AssertionError(rule + ": malformed DER",e); }
    }

    /** Sections 3.1 and 3.2.2, Tables 1,4,5: all four active asymmetric card key uses. */
    public static void cardKey(byte[] subjectPublicKeyInfo) {
        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(der(subjectPublicKeyInfo,"78-SPKI"));
            require(spki.getPublicKeyData().getPadBits()==0,"78-SPKI","key BIT STRING has unused bits");
            AlgorithmIdentifier algorithm = spki.getAlgorithm();
            String oid = algorithm.getAlgorithm().getId();
            if (RSA.equals(oid)) {
                require(algorithm.getParameters() instanceof ASN1Null,"78-SPKI","rsaEncryption parameters must be NULL (RFC3279 2.3.1)");
                ASN1Sequence rsa=ASN1Sequence.getInstance(spki.parsePublicKey());
                require(rsa.size()==2 && ASN1Integer.getInstance(rsa.getObjectAt(0)).getValue().signum()>0
                        && ASN1Integer.getInstance(rsa.getObjectAt(1)).getValue().signum()>0,"78-SPKI","RSA integers must be positive");
                org.bouncycastle.asn1.pkcs.RSAPublicKey key = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(rsa);
                int size = key.getModulus().bitLength();
                require(key.getModulus().signum()>0 && (size==2048 || size==3072),"78-CARD-KEY","RSA modulus must be 2048 or 3072 bits");
                require(BigInteger.valueOf(65537).equals(key.getPublicExponent()),"78-RSA-EXPONENT","PIV RSA exponent must be 65537");
            } else if (EC.equals(oid)) {
                require(algorithm.getParameters() instanceof ASN1ObjectIdentifier,"78-SPKI","named-curve OID required");
                String curve = ((ASN1ObjectIdentifier)algorithm.getParameters()).getId();
                require(P256.equals(curve) || P384.equals(curve),"78-CARD-KEY","only P-256 or P-384 allowed");
                X9ECParameters domain = ECNamedCurveTable.getByOID(new ASN1ObjectIdentifier(curve));
                var point = domain.getCurve().decodePoint(spki.getPublicKeyData().getBytes());
                require(!point.isInfinity() && point.isValid(),"78-SPKI","invalid EC public point");
            } else require(false,"78-SPKI","disallowed public-key algorithm " + oid);
        } catch (Exception e) { throw new AssertionError("78-SPKI: malformed public key",e); }
    }

    /** Section 3.2.1 Tables 2/3 plus RFC4055 3,5 and RFC5758 3.2.
     * Only AlgorithmIdentifier is checked, not the issuer key or the signature bytes.
     */
    public static void signatureAlgorithm(byte[] encoded) {
        String rule = "78-CERT-SIGNATURE";
        try {
            AlgorithmIdentifier algorithm = AlgorithmIdentifier.getInstance(der(encoded,rule));
            String oid = algorithm.getAlgorithm().getId();
            ASN1Encodable params = algorithm.getParameters();
            if (Set.of("1.2.840.113549.1.1.11","1.2.840.113549.1.1.12").contains(oid)) {
                require(params==null || params instanceof ASN1Null,rule,"RSA SHA2 parameters must be NULL or absent");
            } else if (Set.of("1.2.840.10045.4.3.2","1.2.840.10045.4.3.3").contains(oid)) {
                require(params==null,rule,"ECDSA parameters must be absent");
            } else if (PSS.equals(oid)) {
                require(params instanceof ASN1Sequence,rule,"PSS parameters must be present");
                int previous = -1;
                for (ASN1Encodable field : ASN1Sequence.getInstance(params)) {
                    require(field instanceof ASN1TaggedObject,rule,"PSS field must be tagged");
                    require(((ASN1TaggedObject)field).isExplicit(),rule,"PSS field must use explicit tagging");
                    int tag = ((ASN1TaggedObject)field).getTagNo();
                    require(tag>previous && tag<=3,rule,"duplicate, unknown or unordered PSS parameter");
                    previous=tag;
                }
                RSASSAPSSparams pss = RSASSAPSSparams.getInstance(params);
                require(Set.of(SHA256,SHA384).contains(pss.getHashAlgorithm().getAlgorithm().getId()),rule,"PSS digest must be SHA-256 or SHA-384");
                ASN1Encodable hashParams=pss.getHashAlgorithm().getParameters();
                require(hashParams==null || hashParams instanceof ASN1Null,rule,"invalid digest parameters");
                require(pss.getMaskGenAlgorithm().getAlgorithm().getId().equals("1.2.840.113549.1.1.8"),rule,"PSS mask algorithm must be MGF1");
                AlgorithmIdentifier mgfHash=AlgorithmIdentifier.getInstance(pss.getMaskGenAlgorithm().getParameters());
                require(mgfHash!=null,rule,"MGF1 hash identifier required");
                require(Set.of("1.3.14.3.2.26","2.16.840.1.101.3.4.2.4",SHA256,SHA384,"2.16.840.1.101.3.4.2.3")
                        .contains(mgfHash.getAlgorithm().getId()),rule,"MGF1 hash not listed in RFC4055 section 2.1");
                require(mgfHash.getParameters()==null || mgfHash.getParameters() instanceof ASN1Null,rule,"invalid MGF1 hash parameters");
                require(pss.getSaltLength().signum()>=0,rule,"negative PSS salt length");
                require(pss.getTrailerField().equals(BigInteger.ONE),rule,"PSS trailer must be 1");
            } else require(false,rule,"disallowed signature algorithm " + oid);
        } catch (Exception e) { throw new AssertionError(rule + ": malformed algorithm identifier",e); }
    }
}
