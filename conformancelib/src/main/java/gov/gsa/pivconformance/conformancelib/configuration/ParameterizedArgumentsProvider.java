package gov.gsa.pivconformance.conformancelib.configuration;

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

import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;

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
		String container = null;
		
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
			container = parameterSource.getContainer(fqmn);
		} else {
			s_logger.warn("ParameterizedArgumentsProvider called without named parameters in dictionary. Resorting to stack.");
			// otherwise pop one off the stack
			parameters = parameterSource.getNextParameter();
		}
		
		String containerOid = null;
		
		if(container != null && !container.isEmpty())
			containerOid = APDUConstants.getStringForFieldNamed(container);

		String containerObj = (containerOid != null) ? containerOid : container;
		
		if(parameters != null) {
			StringBuffer sb = new StringBuffer("");
			for(String p : parameters) {
				if (sb.length() > 0) sb.append(",");
				sb.append(p.replaceAll("[\n\r\b\t]", ""));
			}
			argList.add(Arguments.of(containerObj, sb.toString()));
		} else {
			argList.add(Arguments.of(containerObj));
		}
		
		return argList.stream();
	}

	/*
	 * 
	 * 		if(parameters != null) {
			// it is feasible that we need to add a block like this... leaving for reference:
			// if(container != null && !container.isEmpty()) {
			// for(String p : parameters) {
			//		argList.add( Arguments.of(container,p));
			//	}
			// }
			for(String p : parameters) {
				argList.add(Arguments.of(p));
			}
		} else if(container != null && !container.isEmpty()) {
			String containerOid = APDUConstants.getStringForFieldNamed(container);
			if(containerOid != null) {
				argList.add(Arguments.of(containerOid));
			} else {
				argList.add(Arguments.of(container));
			}
		}
		
	 */
}
