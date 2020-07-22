package gov.gsa.conformancelib.configuration;

import javax.smartcardio.CardTerminal;

import gov.gsa.pivconformance.card.client.AbstractPIVApplication;
import gov.gsa.pivconformance.card.client.CardHandle;

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

    public String getGlobalPin() {
		return m_globalPin;
	}

	public void setGlobalPin(String globalPin) {
		m_globalPin = globalPin;
	}

	public CardTerminal getTerminal() {
		return m_terminal;
	}

	public void setTerminal(CardTerminal terminal) {
		m_terminal = terminal;
	}

	public CardHandle getCardHandle() {
		return m_cardHandle;
	}

	public void setCardHandle(CardHandle cardHandle) {
		m_cardHandle = cardHandle;
	}
	
	public LOGIN_STATUS getLastLoginStatus() {
		return m_lastLoginStatus;
	}

	public void setLastLoginStatus(LOGIN_STATUS lastLoginStatus) {
		m_lastLoginStatus = lastLoginStatus;
	}

	public AbstractPIVApplication getPivHandle() {
		return m_pivHandle;
	}

	public void setPivHandle(AbstractPIVApplication pivHandle) {
		m_pivHandle = pivHandle;
	}

	public enum LOGIN_STATUS {
		LOGIN_SUCCESS,
		LOGIN_FAIL,
		LOGIN_NOT_TRIED
	}

	private String m_applicationPin = null;
    private String m_globalPin = null;
    
    private CardTerminal m_terminal = null;
    private CardHandle m_cardHandle = null;
    private AbstractPIVApplication m_pivHandle = null;
    
    private LOGIN_STATUS m_lastLoginStatus;

    private CardSettingsSingleton() {
    	reset();
    }
    private static final CardSettingsSingleton INSTANCE = new CardSettingsSingleton();
    public static CardSettingsSingleton getInstance()
    {
        return INSTANCE;
    }
    
    // clear all saved status. should only be called when a card is changed
    public void reset() {
    	m_readerIndex = -1;
    	m_applicationPin = null;
    	m_globalPin = null;
    	m_terminal = null;
    	m_pivHandle = null;
    	m_cardHandle = null;
    	m_lastLoginStatus = LOGIN_STATUS.LOGIN_NOT_TRIED;
    }


}
