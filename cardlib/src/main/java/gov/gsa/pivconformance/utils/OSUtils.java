package gov.gsa.pivconformance.utils;

import java.nio.file.Path;
import java.nio.file.Paths;

import gov.gsa.pivconformance.utils.OSUtils.OSTYPE;

public class OSUtils {
	
	public enum  OSTYPE {
		WINDOWS(10),
		OSX(20),
		LINUX(30);
		   
        private int ostypeValue;

        private OSTYPE (int ostypeValue) {
                this.ostypeValue = ostypeValue;
        }
	}

	public OSUtils () {
		
	}
	 
	/**
	 * Get one of the three supported operating system types
	 * @return manufactured OSTYPE from environment
	 * 
	 */
	public static OSTYPE getOSType() {
		OSTYPE rv = OSTYPE.LINUX;
		String osName = System.getProperty("os.name");
		if (osName.toLowerCase().contains("windows")) {
			rv = OSTYPE.WINDOWS;
		} else if (osName.toLowerCase().startsWith("mac")) {
			rv = OSTYPE.OSX;
		} else if (osName.toLowerCase().contains("linux")) {
			rv = OSTYPE.LINUX;
		}		
		return rv;
	}
	
	/**
	 * Get the location of the temp directory
	 * @return the location of the temp directory
	 */
	
	public static String getTempDir() {
        OSTYPE os = OSUtils.getOSType();
        String rv;

        switch (os) {
        case WINDOWS:
        	rv = System.getenv("TEMP");
        	break;
        case OSX:
        case LINUX:
        	rv = "/tmp";
        default:
        	rv = System.getenv("TEMP");
        }
        
        return rv;
	}
}
