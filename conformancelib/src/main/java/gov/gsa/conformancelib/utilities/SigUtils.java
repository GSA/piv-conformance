/*
 * Copyright 2017 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package gov.gsa.conformancelib.utilities;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Selector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for the signature / timestamp examples.
 * 
 * @author Tilman Hausherr
 */
public class SigUtils
{
    private static final Logger s_logger = LoggerFactory.getLogger(SigUtils.class);

    private SigUtils()
    {
    }

    /**
     * Log if the certificate is not valid for signature usage. Doing this
     * anyway results in Adobe Reader failing to validate the PDF.
     *
     * @param x509Certificate 
     * @throws java.security.cert.CertificateParsingException 
     */
    public static void checkCertificateUsage(X509Certificate x509Certificate)
            throws CertificateParsingException
    {
        // Check whether signer certificate is "valid for usage"
        // https://stackoverflow.com/a/52765021/535646
        // https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSig/changes.html#id1
        boolean[] keyUsage = x509Certificate.getKeyUsage();
        if (keyUsage != null && !keyUsage[0] && !keyUsage[1])
        {
            // (unclear what "signTransaction" is)
            // https://tools.ietf.org/html/rfc5280#section-4.2.1.3
            s_logger.error("Certificate key usage does not include " +
                    "digitalSignature nor nonRepudiation");
        }
        List<String> extendedKeyUsage = x509Certificate.getExtendedKeyUsage();
        if (extendedKeyUsage != null &&
            !extendedKeyUsage.contains(KeyPurposeId.id_kp_emailProtection.toString()) &&
            !extendedKeyUsage.contains(KeyPurposeId.id_kp_codeSigning.toString()) &&
            !extendedKeyUsage.contains(KeyPurposeId.anyExtendedKeyUsage.toString()) &&
            !extendedKeyUsage.contains("1.2.840.113583.1.1.5") &&
            // not mentioned in Adobe document, but tolerated in practice
            !extendedKeyUsage.contains("1.3.6.1.4.1.311.10.3.12"))
        {
            s_logger.error("Certificate extended key usage does not include " +
                    "emailProtection, nor codeSigning, nor anyExtendedKeyUsage, " +
                    "nor 'Adobe Authentic Documents Trust'");
        }
    }

    /**
     * Log if the certificate is not valid for timestamping.
     *
     * @param x509Certificate 
     * @throws java.security.cert.CertificateParsingException 
     */
    public static void checkTimeStampCertificateUsage(X509Certificate x509Certificate)
            throws CertificateParsingException
    {
        List<String> extendedKeyUsage = x509Certificate.getExtendedKeyUsage();
        // https://tools.ietf.org/html/rfc5280#section-4.2.1.12
        if (extendedKeyUsage != null &&
            !extendedKeyUsage.contains(KeyPurposeId.id_kp_timeStamping.toString()))
        {
            s_logger.error("Certificate extended key usage does not include timeStamping");
        }
    }

    /**
     * Log if the certificate is not valid for responding.
     *
     * @param x509Certificate 
     * @throws java.security.cert.CertificateParsingException 
     */
    public static void checkResponderCertificateUsage(X509Certificate x509Certificate)
            throws CertificateParsingException
    {
        List<String> extendedKeyUsage = x509Certificate.getExtendedKeyUsage();
        // https://tools.ietf.org/html/rfc5280#section-4.2.1.12
        if (extendedKeyUsage != null &&
            !extendedKeyUsage.contains(KeyPurposeId.id_kp_OCSPSigning.toString()))
        {
            s_logger.error("Certificate extended key usage does not include OCSP responding");
        }
    }

    static public TimeStampToken extractTimeStampTokenFromSignerInformation(SignerInformation signerInformation)
            throws CMSException, IOException, TSPException
    {
        if (signerInformation.getUnsignedAttributes() == null)
        {
            return null;
        }
        AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
        // https://stackoverflow.com/questions/1647759/how-to-validate-if-a-signed-jar-contains-a-timestamp
        Attribute attribute = unsignedAttributes.get(
                PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
        if (attribute == null)
        {
            return null;
        }
        ASN1Object obj = (ASN1Object) attribute.getAttrValues().getObjectAt(0);
        CMSSignedData signedTSTData = new CMSSignedData(obj.getEncoded());
        return new TimeStampToken(signedTSTData);
    }

    public static void validateTimestampToken(TimeStampToken timeStampToken)
            throws IOException, CertificateException, TSPException, OperatorCreationException
    {
        // https://stackoverflow.com/questions/42114742/
        @SuppressWarnings("unchecked") // TimeStampToken.getSID() is untyped
        Collection<X509CertificateHolder> tstMatches =
                timeStampToken.getCertificates().getMatches((Selector<X509CertificateHolder>) timeStampToken.getSID());
        X509CertificateHolder certificateHolder = tstMatches.iterator().next();
        SignerInformationVerifier siv = 
                new JcaSimpleSignerInfoVerifierBuilder().setProvider(SecurityProvider.getProvider()).build(certificateHolder);
        timeStampToken.validate(siv);
    }
}
