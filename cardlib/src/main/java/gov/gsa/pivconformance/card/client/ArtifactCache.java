/**
 * 
 */
package gov.gsa.pivconformance.card.client;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages the local artifact cache to minimize disk I/O
 *
 */

public class ArtifactCache {
	private static final Logger s_logger = LoggerFactory.getLogger(ArtifactCache.class);
	private String m_artifactDir = null;
	private ArrayList<byte[]> m_artifactCache = null;
	
	public ArtifactCache(String subDir) {
		if (m_artifactDir == null)
			init(subDir);
	}
	
	void init(String subDir) {
		String sep = File.separator;
        String cwd = Paths.get(".").toAbsolutePath().normalize().toString();
        String artifactDir = null;

        artifactDir = cwd + sep + subDir;
        
        if (!Files.exists(Paths.get(artifactDir))) {
            File file = new File(artifactDir);
            boolean exists = file.mkdir();
            if (exists){
               s_logger.debug("Directory " + artifactDir + " created successfully");
            } else{
               System.out.println("Couldn’t create directory " + artifactDir);
            }
        }
        
        m_artifactCache = new ArrayList<byte[]>();
        m_artifactDir = artifactDir;
	}
	
	/**
	 * Exports an X.509 certificate
	 * 
	 * @param containerName
	 * @param bytes
	 * @return
	 */

	public boolean saveObject(String containerName, byte[] bytes) {
		boolean result = false;
		if (!m_artifactCache.contains(bytes)) {
			String filePath = m_artifactDir + File.separator  + containerName;
	    	try {
	    		FileOutputStream fos = new FileOutputStream(filePath);
	    		fos.write(bytes);
	    		fos.close();
	    		s_logger.debug("Wrote " + filePath);
				m_artifactCache.add(bytes);
	    		result = true;
	    	} catch (IOException e) {
	    		// TODO Auto-generated catch block
	    		e.printStackTrace();
	    	}
		}
    	return result;
	}
}
