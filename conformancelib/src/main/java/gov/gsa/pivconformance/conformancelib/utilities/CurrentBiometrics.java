package gov.gsa.pivconformance.conformancelib.utilities;

import java.nio.ByteBuffer;
import java.time.DateTimeException;
import java.time.LocalDateTime;
import java.util.Arrays;
import static gov.gsa.pivconformance.conformancelib.utilities.CurrentDataModel.require;

/** SP800-76-2 Tables 13-15: on-card fingerprint CBEFF header only. */
public final class CurrentBiometrics {
    private CurrentBiometrics() { }
    private static final String RULE="76-CBEFF-HEADER";
    private static int u(byte b) { return b&255; }
    private static LocalDateTime date(byte[] b,int p) {
        require(b[p+7]=='Z',RULE,"CBEFF date must use UTC Z");
        require(u(b[p])<=99 && u(b[p+1])<=99,RULE,"invalid binary year pair");
        try { return LocalDateTime.of(100*u(b[p])+u(b[p+1]),u(b[p+2]),u(b[p+3]),u(b[p+4]),u(b[p+5]),u(b[p+6])); }
        catch (DateTimeException e) { throw new AssertionError(RULE+": invalid binary calendar date",e); }
    }
    public static void fingerprintHeader(byte[] cbeff,byte[] chuidFascn) {
        require(cbeff!=null && cbeff.length>=88,RULE,"CBEFF header requires 88 bytes");
        require(chuidFascn!=null && chuidFascn.length==25,RULE,"CHUID FASC-N requires 25 bytes");
        require(cbeff[0]==3,RULE,"patron version must be 03");
        require(cbeff[1]==0x0d,RULE,"mandatory fingerprint template must be signed and unencrypted");
        long bdb=Integer.toUnsignedLong(ByteBuffer.wrap(cbeff,2,4).getInt());
        int sb=(u(cbeff[6])<<8)|u(cbeff[7]);
        require(bdb>0 && sb>0 && 88L+bdb+sb==cbeff.length,RULE,"CBEFF declared lengths do not match record");
        require(cbeff[8]==0 && cbeff[9]==0x1b && cbeff[10]==2 && cbeff[11]==1,RULE,"fingerprint template format must be 001B/0201");
        LocalDateTime created=date(cbeff,12),start=date(cbeff,20);
        date(cbeff,28);
        require(!start.isBefore(created),RULE,"validity starts before creation");
        require(cbeff[36]==0 && cbeff[37]==0 && cbeff[38]==8,RULE,"fingerprint biometric type must be 000008");
        require((cbeff[39]&0xe0)==0x80,RULE,"fingerprint template must be processed data");
        require(cbeff[40]>=-2 && cbeff[40]<=100,RULE,"quality must be a signed value in [-2,100]");
        boolean nul=false;
        for (int i=41;i<59;i++) {
            if (cbeff[i]==0) { nul=true;break; }
            require(cbeff[i]>=0x20 && cbeff[i]<=0x7e,RULE,"creator prefix must be printable ASCII");
        }
        require(nul,RULE,"creator requires null terminator within 18 bytes");
        require(Arrays.equals(Arrays.copyOfRange(cbeff,59,84),chuidFascn),RULE,"CBEFF FASC-N differs from CHUID");
        for(int i=84;i<88;i++)require(cbeff[i]==0,RULE,"reserved bytes must be zero");
    }
}
