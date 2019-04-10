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
			Method target = testMethod.get();
			String methodName = target.getName();
			String className = target.getDeclaringClass().getName();
			String fqmn = className;
			Class<?> testClass;
			try {
				testClass = Class.forName(className);
				for(Method m : testClass.getDeclaredMethods()) {
					if(m.getName().contentEquals(methodName)) {
						fqmn += "#" + m.getName() + "(";
						Class<?>[] methodParameters = m.getParameterTypes();
						int nMethodParameters = 0;
						for(Class<?> c : methodParameters) {
							if(nMethodParameters >= 1) {
								fqmn += ", ";
							}
							fqmn += c.getName();
							nMethodParameters++;
						}
						fqmn += ")";
					}

				}
			} catch (ClassNotFoundException e) {
				s_logger.error("{} was discovered by junit but could not be loaded.", fqmn);
			}

			parameters = parameterSource.getNamedParameter(fqmn);			
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
