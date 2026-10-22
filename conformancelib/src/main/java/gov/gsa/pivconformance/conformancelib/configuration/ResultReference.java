package gov.gsa.pivconformance.conformancelib.configuration;

import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Reviewed source for the predicate asserted by an existing CCT atom. */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@Repeatable(ResultReference.Sources.class)
public @interface ResultReference {
    String publication();
    String location();
    String url();
    String scope();
    /** Verbatim source excerpt; explanatory wording belongs in scope. */
    String excerpt() default "";
    /** Official document page or section, with a stable fragment where available. */
    String documentUrl() default "";
    /** Original CCT container field names; empty means all containers using this atom. */
    String[] containers() default {};

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    @interface Sources {
        ResultReference[] value();
    }
}
