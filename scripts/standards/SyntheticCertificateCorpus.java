import java.nio.file.*;
import java.math.BigInteger;
import java.security.*;
import java.time.Instant;
import java.util.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Lab-only synthetic certificates. Seed is public; generated keys must never be used operationally. */
public class SyntheticCertificateCorpus {
    static final Instant FROM=Instant.parse("2020-01-01T00:00:00Z"), TO=Instant.parse("2040-01-01T00:00:00Z");
    static final String[] POLICIES={"2.16.840.1.101.3.2.1.3.18","2.16.840.1.101.3.2.1.3.7","2.16.840.1.101.3.2.1.3.7","2.16.840.1.101.3.2.1.3.2","2.16.840.1.101.3.2.1.3.18","2.16.840.1.101.3.2.1.3.6","2.16.840.1.101.3.2.1.3.18","2.16.840.1.101.3.2.1.48.13","2.16.840.1.101.3.2.1.48.9","2.16.840.1.101.3.2.1.48.11","2.16.840.1.101.3.2.1.48.4","2.16.840.1.101.3.2.1.48.9"};
    static byte[] issue(PublicKey key,PrivateKey signer,X500Name issuer,X500Name subject,int serial,
                        String policy,boolean ca,Instant from,Instant to) throws Exception {
        var builder=new JcaX509v3CertificateBuilder(issuer,BigInteger.valueOf(serial),Date.from(from),Date.from(to),subject,key);
        builder.addExtension(Extension.basicConstraints,true,new BasicConstraints(ca));
        builder.addExtension(Extension.keyUsage,true,new KeyUsage(ca ? KeyUsage.keyCertSign|KeyUsage.cRLSign : KeyUsage.digitalSignature));
        if (policy!=null) builder.addExtension(Extension.certificatePolicies,false,new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier(policy))));
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(signer)).getEncoded();
    }
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        SecureRandom random=SecureRandom.getInstance("SHA1PRNG","SUN");
        random.setSeed("CCT public deterministic synthetic corpus v1; never production".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA","BC");
        generator.initialize(2048,random);
        KeyPair ca=generator.generateKeyPair(),leaf=generator.generateKeyPair();
        X500Name issuer=new X500Name("CN=CCT Synthetic Test Root,O=Test Only");
        Path dest=Path.of(args[0]);Files.createDirectories(dest);
        Files.write(dest.resolve("root.der"),issue(ca.getPublic(),ca.getPrivate(),issuer,issuer,1,null,true,FROM,TO));
        for (int i=0;i<POLICIES.length;i++) Files.write(dest.resolve(String.format("policy-%02d.der",i+1)),
                issue(leaf.getPublic(),ca.getPrivate(),issuer,new X500Name("CN=Synthetic Policy Vector "+(i+1)+",O=Test Only"),i+2,POLICIES[i],false,FROM,TO));
        Files.write(dest.resolve("no-policy.der"),issue(leaf.getPublic(),ca.getPrivate(),issuer,new X500Name("CN=Synthetic No Policy"),30,null,false,FROM,TO));
        Files.write(dest.resolve("expired.der"),issue(leaf.getPublic(),ca.getPrivate(),issuer,new X500Name("CN=Synthetic Expired"),31,POLICIES[0],false,FROM,Instant.parse("2025-01-01T00:00:00Z")));
        byte[] bad=Files.readAllBytes(dest.resolve("policy-01.der"));bad[bad.length-1]^=1;
        Files.write(dest.resolve("bad-signature.der"),bad);
        Files.write(dest.resolve("malformed.der"),new byte[]{0x30,0x7f,0});
        StringBuilder index=new StringBuilder("# file\tsha256\n");
        try(var paths=Files.list(dest)) {
            for(Path p:paths.filter(p->p.toString().endsWith(".der")).sorted().toList())
                index.append(p.getFileName()).append('\t').append(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p)))).append('\n');
        }
        Files.writeString(dest.resolve("MANIFEST.tsv"),index.toString());
    }
}
