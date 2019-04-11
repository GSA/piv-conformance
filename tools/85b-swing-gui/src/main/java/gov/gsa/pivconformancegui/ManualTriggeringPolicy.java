package gov.gsa.pivconformancegui;

import java.io.File;

import ch.qos.logback.core.rolling.TriggeringPolicyBase;

public class ManualTriggeringPolicy<E> extends TriggeringPolicyBase<E> {

	@Override
	public boolean isTriggeringEvent(File activeFile, E event) {
		return false;
	}

}
