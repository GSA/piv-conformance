package gov.gsa.conformancelib.configuration;

public final class CardSettingsSingleton {

    public int getReaderIndex() {
        return m_readerIndex;
    }

    public void setReaderIndex(int readerIndex) {
        this.m_readerIndex = readerIndex;
    }

    private int m_readerIndex;

    public String getApplicationPin() {
        return m_applicationPin;
    }

    public void setApplicationPin(String applicationPin) {
        this.m_applicationPin = applicationPin;
    }

    private String m_applicationPin;

    private CardSettingsSingleton() {}
    private static final CardSettingsSingleton INSTANCE = new CardSettingsSingleton();
    public static CardSettingsSingleton getInstance()
    {
        return INSTANCE;
    }


}
