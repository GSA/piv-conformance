package gov.gsa.e4.rcp.cct.services.internal;

import org.eclipse.e4.core.contexts.ContextFunction;
import org.eclipse.e4.core.contexts.ContextInjectionFactory;
import org.eclipse.e4.core.contexts.IContextFunction;
import org.eclipse.e4.core.contexts.IEclipseContext;
import org.eclipse.e4.ui.model.application.MApplication;
import org.osgi.service.component.annotations.Component;

import gov.gsa.e4.rcp.cct.model.ICCTService;

@Component(service = IContextFunction.class, property = "service.context.key=gov.gsa.e4.rcp.cct.model.ICCTService")
public class CCTServiceContextFunction extends ContextFunction {

	@Override
	public Object compute(IEclipseContext context, String contextKey) {
		ICCTService impl = ContextInjectionFactory.make(MyCCTServiceImpl.class, context);
		MApplication application = context.get(MApplication.class);
		application.getContext().set(ICCTService.class, impl);
		return impl;
	}
}












