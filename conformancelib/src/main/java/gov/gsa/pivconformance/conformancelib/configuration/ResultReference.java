package gov.gsa.pivconformance.conformancelib.configuration;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Reviewed source for the predicate asserted by an existing CCT atom. */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface ResultReference {
    String publication();
    String location();
    String url();
    String scope();
}
