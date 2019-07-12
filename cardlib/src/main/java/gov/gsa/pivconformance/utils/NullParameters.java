package gov.gsa.pivconformance.utils;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Primitive;


public class NullParameters implements ASN1Encodable{

	@Override
	public ASN1Primitive toASN1Primitive() {
		byte[] NULL = {0x05, 0x00};
		return ASN1Null.getInstance(NULL);
	}

}
