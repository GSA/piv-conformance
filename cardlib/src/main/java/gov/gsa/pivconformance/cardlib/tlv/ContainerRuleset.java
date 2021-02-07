package gov.gsa.pivconformance.cardlib.tlv;

import java.util.HashMap;
import java.util.LinkedHashMap;

import gov.gsa.pivconformance.cardlib.tlv.TagLengthRule;

/**
 * Each ContainerRuleset consists of a container name and HashMap of TagLengthRules for each tag in the container

 */
public class ContainerRuleset {
	private String m_containerName = null;
	private LinkedHashMap<BerTag, TagLengthRule> m_tagRuleset = new LinkedHashMap<BerTag, TagLengthRule>();
	
	public ContainerRuleset(String containerName) {
		this.m_containerName = containerName;
		this.m_tagRuleset = new LinkedHashMap<BerTag, TagLengthRule>();
	}

	/**
	 * Adds a container length rule to this container's ruleset
	 * @param tag container tag
	 * @param RULE length rule to apply
	 */
	public void add(BerTag tag, TagLengthRule RULE) {
		m_tagRuleset.put(tag, RULE);
	}
	
	/**
	 * Gets the list of tags and rules for this container
	 * @return
	 */
	
	public String getContainerName() {
		return m_containerName;
	}
	/**
	 * Gets the list of tags and rules for this container
	 * @return
	 */
	
	public HashMap<BerTag, TagLengthRule> getTagRuleset() {
		return m_tagRuleset;
	}
}
