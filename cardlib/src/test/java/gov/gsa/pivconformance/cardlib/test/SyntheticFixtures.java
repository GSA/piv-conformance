package gov.gsa.pivconformance.cardlib.test;

import gov.gsa.pivconformance.cardlib.card.client.APDUUtils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.cms.*;
import org.bouncycastle.operator.jcajce.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.*;

/** Generates test resources from invented data without saving the signing key. */
public final class SyntheticFixtures {
    private SyntheticFixtures() { }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Expected the synthetic resource directory");
        Path output = Files.createDirectories(Path.of(args[0]));
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair key = generator.generateKeyPair();
        X500Name name = new X500Name("CN=CCT synthetic test fixture");
        byte[] guid = HexFormat.of().parseHex("00112233445546778899aabbccddeeff");
        byte[] holder = HexFormat.of().parseHex("102132435465476889abcdef01234567");
        var builder = new JcaX509v3CertificateBuilder(name, java.math.BigInteger.ONE,
                new Date(1704067200000L), new Date(1893456000000L), name, key.getPublic());
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier,
                        "urn:uuid:00112233-4455-4677-8899-aabbccddeeff")));
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())));
        cert.verify(key.getPublic());
        String pem = "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, new byte[]{10})
                .encodeToString(cert.getEncoded()) + "\n-----END CERTIFICATE-----\n";
        Files.writeString(output.resolve("certificate.pem"), pem, StandardCharsets.US_ASCII);

        byte[] ccc = new byte[0];
        for (int tag : new int[]{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                0xfa, 0xfb, 0xfc, 0xfd, 0xfe}) {
            byte[] value = tag == 0xf0 ? new byte[21] : tag == 0xf5 ? new byte[]{0x10} : new byte[0];
            ccc = concat(ccc, tlv(tag, value));
        }
        Files.write(output.resolve("ccc.bin"), ccc);
        Files.write(output.resolve("discovery.bin"), tlv(0x7e, concat(
                tlv(0x4f, HexFormat.of().parseHex("a000000308000010000100")),
                APDUUtils.getTLV(new byte[]{0x5f, 0x2f}, new byte[]{0x60, 0x10}))));
        Files.write(output.resolve("printed.bin"), concat(tlv(1, ascii("CCT SYNTHETIC TEST")),
                tlv(2, ascii("TEST")), tlv(4, ascii("20301231")), tlv(5, ascii("000000000")),
                tlv(6, ascii("CCT TEST ONLY")), tlv(0xfe, new byte[0])));

        byte[] fields = concat(tlv(0x30, fascn()), tlv(0x34, guid), tlv(0x35, ascii("20301231")),
                tlv(0x36, holder));
        Files.write(output.resolve("chuid.bin"), concat(fields, tlv(0x3e,
                cms(concat(fields, tlv(0xfe, new byte[0])), "2.16.840.1.101.3.6.1", false, key, cert)),
                tlv(0xfe, new byte[0])));

        // Header-only records: no JPEG/portrait, minutiae, or captured fingerprint payload.
        byte[] face = new byte[46];
        System.arraycopy(ascii("FAC\0" + "010\0"), 0, face, 0, 8);
        ByteBuffer.wrap(face).putInt(8, face.length).putShort(12, (short) 1);
        face[34] = 1; face[35] = 0; face[40] = 1; face[41] = 2;
        Files.write(output.resolve("face-header.bin"), biometric(face, key, cert));
        byte[] fingerprint = new byte[24];
        System.arraycopy(ascii("FMR\0" + " 20\0"), 0, fingerprint, 0, 8);
        Files.write(output.resolve("fingerprint-header.bin"), biometric(fingerprint, key, cert));

        // The parser test needs a CMS payload, not a complete LDS hash table.
        Files.write(output.resolve("security.bin"), concat(tlv(0xba, new byte[]{1, 0x30, 0x30}),
                tlv(0xbb, cms(ascii("CCT SYNTHETIC SECURITY PAYLOAD"), "2.23.136.1.1.1", true, key, cert)),
                tlv(0xfe, new byte[0])));
    }

    private static byte[] biometric(byte[] record, KeyPair key, X509Certificate cert) throws Exception {
        byte[] header = new byte[88];
        header[0] = 3;
        ByteBuffer.wrap(header).putInt(2, record.length);
        byte[] date = HexFormat.of().parseHex("202401010000005a");
        for (int offset : new int[]{12, 20, 28}) System.arraycopy(date, 0, header, offset, date.length);
        byte[] signature = cms(concat(header, record), "1.3.6.1.4.1.601.1", false, key, cert);
        ByteBuffer.wrap(header).putShort(6, (short) signature.length);
        byte[] signed = concat(header, record);
        byte[] finalSignature = cms(signed, "1.3.6.1.4.1.601.1", false, key, cert);
        if (finalSignature.length != signature.length) throw new IllegalStateException("CMS length changed");
        return concat(tlv(0xbc, concat(signed, finalSignature)), tlv(0xfe, new byte[0]));
    }

    private static byte[] cms(byte[] content, String type, boolean encapsulate,
            KeyPair key, X509Certificate cert) throws Exception {
        X500Name name = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
        var signer = new SignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build(),
                algorithm -> new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE));
        signer.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(
                new Attribute(new ASN1ObjectIdentifier("2.16.840.1.101.3.6.5"), new DERSet(name)))));
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(signer.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate()),
                new X509CertificateHolder(cert.getEncoded())));
        generator.addCertificates(new JcaCertStore(List.of(cert)));
        return generator.generate(new CMSProcessableByteArray(new ASN1ObjectIdentifier(type), content),
                encapsulate).getEncoded();
    }

    private static byte[] fascn() {
        // Invented test fields: sentinels/separators, odd character parity and LRC.
        String symbols = "B9999D9999D000001D1D1D0000000000199991F";
        byte[] result = new byte[25];
        int lrc = 0;
        for (int i = 0; i < 40; i++) {
            int value = i < 39 ? Character.digit(symbols.charAt(i), 16) : lrc;
            if (i < 39) lrc ^= value;
            int encoded = value | ((Integer.bitCount(value) % 2 == 0 ? 1 : 0) << 4);
            for (int bit = 0; bit < 5; bit++)
                if ((encoded & (1 << bit)) != 0) result[(i * 5 + bit) / 8] |= 1 << (7 - (i * 5 + bit) % 8);
        }
        return result;
    }

    private static byte[] ascii(String value) { return value.getBytes(StandardCharsets.US_ASCII); }
    private static byte[] tlv(int tag, byte[] value) { return APDUUtils.getTLV(new byte[]{(byte) tag}, value); }
    private static byte[] concat(byte[]... values) {
        var result = new java.io.ByteArrayOutputStream();
        for (byte[] value : values) result.writeBytes(value);
        return result.toByteArray();
    }
}
