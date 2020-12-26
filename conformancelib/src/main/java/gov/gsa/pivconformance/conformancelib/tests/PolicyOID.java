package gov.gsa.pivconformance.conformancelib.tests;

public enum PolicyOID {
    ID_FPKI_CERTPCY_PIVI_HARDWARE("2.16.840.1.101.3.2.1.3.18"),
    ID_FPKI_COMMON_HARDWARE("2.16.840.1.101.3.2.1.3.7"),
    ID_FPKI_COMMON_POLICY("2.16.840.1.101.3.2.1.3.6"),
    ID_FPKI_CERTPCY_BASICASSURANCE("2.16.840.1.101.3.2.1.3.2"),
    TEST_ID_FPKI_COMMON_CARDAUTH("2.16.840.1.101.3.2.1.48.13"),
    TEST_ID_FPKI_COMMON_AUTHENTICATION("2.16.840.1.101.3.2.1.48.11"),
    TEST_ID_FPKI_COMMON_HARDWARE("2.16.840.1.101.3.2.1.48.9"),
    TEST_ID_FPKI_CERTPCY_MEDIUMHARDWARE("2.16.840.1.101.3.2.1.48.4");

    private final String value;

    PolicyOID(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
