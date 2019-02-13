package gov.gsa.e4.rcp.cct.services.internal;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import javax.inject.Inject;

import org.eclipse.e4.core.services.events.IEventBroker;

import gov.gsa.e4.rcp.cct.events.MyEventConstants;
import gov.gsa.e4.rcp.cct.model.ICCTService;
import gov.gsa.e4.rcp.cct.model.TestCase;

public class MyCCTServiceImpl implements ICCTService {

	private static AtomicInteger current = new AtomicInteger(1);
	private List<TestCase> ccts;

	// use dependency injection in MyCCTServiceImpl
	@Inject
	private IEventBroker broker;

	public MyCCTServiceImpl() {
		ccts = createInitialModel();
	}

	@Override
	public void getTestCases(Consumer<List<TestCase>> cctsConsumer) {
		// always pass a new copy of the data
		cctsConsumer.accept(ccts.stream().map(TestCase::copy).collect(Collectors.toList()));
	}

	protected List<TestCase> getTestCasesInternal() {
		return ccts;
	}

	// create or update an existing instance
	@Override
	public synchronized boolean saveTestCase(TestCase newTestCase) {
		Optional<TestCase> cctOptional = findById(newTestCase.getId());

		// get the actual test case or create a new one
		TestCase cct = cctOptional.orElse(new TestCase(current.getAndIncrement()));
		cct.setSummary(newTestCase.getSummary());
		cct.setDescription(newTestCase.getDescription());
		cct.setDone(newTestCase.isDone());

		// send out events
		if (cctOptional.isPresent()) {
			broker.post(MyEventConstants.TEST_SECTION_UPDATE,
					createEventData(MyEventConstants.TEST_SECTION_UPDATE, String.valueOf(cct.getId())));
		} else {
			ccts.add(cct);
			broker.post(MyEventConstants.TEST_SECTION_NEW,
					createEventData(MyEventConstants.TEST_SECTION_NEW, String.valueOf(cct.getId())));
		}
		return true;
	}

	@Override
	public Optional<TestCase> getTestCase(long id) {
		return findById(id).map(TestCase::copy);
	}

	@Override
	public boolean deleteTestCase(long id) {
		Optional<TestCase> deleteTestCase = findById(id);

		deleteTestCase.ifPresent(cct -> {
			ccts.remove(cct);
			
			// configure the event
			broker.post(MyEventConstants.TEST_SECTION_DELETE,
					createEventData(MyEventConstants.TEST_SECTION_DELETE, String.valueOf(cct.getId())));
		});

		return deleteTestCase.isPresent();
	}

	private List<TestCase> createInitialModel() {
		List<TestCase> list = new ArrayList<>();
		return list;
	}

	private TestCase createTestCase(String summary, String description) {
		return new TestCase(current.getAndIncrement(), summary, description, false, new Date());
	}

	private Optional<TestCase> findById(long id) {
		return getTestCasesInternal().stream().filter(t -> t.getId() == id).findAny();
	}

	private Map<String, String> createEventData(String topic, String cctId) {
		Map<String, String> map = new HashMap<>();
		// in case the receiver wants to check the topic
		map.put(MyEventConstants.TEST_SECTION, topic);
		// which task has changed
		map.put(TestCase.FIELD_ID, cctId);
		return map;
	}
}
