package gov.gsa.conformancelib.configuration;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ParameterizedArgumentsProvider implements ArgumentsProvider {
	private static Logger s_logger = LoggerFactory.getLogger(ParameterUtils.class);
	
	public ParameterizedArgumentsProvider() {
	}

	@Override
	public Stream<? extends Arguments> provideArguments(ExtensionContext context) throws Exception {
		ParameterProviderSingleton parameterSource = ParameterProviderSingleton.getInstance();
		List<Arguments> argList = new ArrayList<Arguments>();
		Optional<Method> testMethod = context.getTestMethod();
		List<String> parameters;
		
		// if there's a method supplied in the context, use it as a key to get parameters from the dictionary
		if(testMethod.isPresent()) {
			parameters = parameterSource.getNamedParameter(testMethod.get().getName());			
		} else {
			s_logger.warn("ParameterizedArgumentsProvider called without named parameters in dictionary. Resorting to stack.");
			// otherwise pop one off the stack
			parameters = parameterSource.getNextParameter();
		}
		
		if(parameters != null) {
			for(String p : parameters) {
				argList.add(Arguments.of(p));
			}
		}
		
		return argList.stream();
	}

}
