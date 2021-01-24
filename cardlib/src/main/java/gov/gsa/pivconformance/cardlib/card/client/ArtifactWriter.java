/**
 * 
 */
package gov.gsa.pivconformance.cardlib.card.client;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages the local artifact cache to minimize disk I/O
 *
 */

public class ArtifactWriter {
	private static final Logger s_logger = LoggerFactory.getLogger(ArtifactWriter.class);
	private static final String m_artifactDir = Paths.get(".").toAbsolutePath().normalize().toString();
	static HashMap<String, ArrayList<String>> m_artifactCache = new HashMap<String, ArrayList<String>>();
	
	public ArtifactWriter(String subDir) {
			init(subDir);
	}
	
	void init(String artifactSubDir) {
		String sep = File.separator;
        String cwd = m_artifactDir;
        String artifactPath = null;

        artifactPath = cwd + sep + artifactSubDir;
        
        if (!Files.exists(Paths.get(artifactPath))) {
            File file = new File(artifactPath);
            boolean exists = file.mkdir();
            if (exists){
               s_logger.debug("Artifact subdirectory " + artifactSubDir + " created successfully");
            } else{
               System.out.println("Couldn’t create directory " + artifactSubDir);
            }
        }
        
        if (m_artifactCache.get(artifactSubDir) == null)
        	m_artifactCache.put(artifactSubDir, new ArrayList<String>());
	}
	
	/**
	 * Exports a container
	 * 
	 * @param containerName
	 * @param bytes
	 * @return
	 */

	public boolean saveObject(String artifactSubDir, String containerName, byte[] bytes) {
		boolean result = false;
		String filePath = m_artifactDir + File.separator + artifactSubDir + File.separator  + containerName;
		if (!m_artifactCache.containsKey(artifactSubDir))
			init(artifactSubDir);

		if (!m_artifactCache.get(artifactSubDir).contains(filePath)) {
	    	try {
	    		FileOutputStream fos = new FileOutputStream(filePath);
	    		fos.write(bytes);
	    		fos.flush();
	    		fos.close();
	    		s_logger.debug("Wrote " + filePath);
				m_artifactCache.get(artifactSubDir).add(filePath);
	    		result = true;
	    	} catch (IOException e) {
	    		// TODO Auto-generated catch block
	    		e.printStackTrace();
	    	}
		} else {
			result = true;
		}
    	return result;
	}
	
	/**
	 * Prepends artifact file names with a time stamp
	 * @param timeStamp time stamp to prepend
	 */
	
	public static boolean prependNames(String timeStamp) {
		boolean result = false;
	    Iterator<?> it = m_artifactCache.entrySet().iterator();
		while (it.hasNext()) {
			@SuppressWarnings("rawtypes")
			Map.Entry mapElement = (Map.Entry)it.next(); 
			@SuppressWarnings("unchecked")
			ArrayList<String> pathList = (ArrayList<String>) mapElement.getValue();
			for (String p : pathList) {
				int index = p.lastIndexOf(File.separator) + 1;
				String baseName = p.substring(index);
				String newBaseName = timeStamp + "-" + baseName;
				File f = new File(p);
				File g = new File(m_artifactDir + File.separator + mapElement.getKey() + File.separator + newBaseName);
				try {
					result = f.renameTo(g);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
		
		return result;
	}

	public static void clean() {
		m_artifactCache = new HashMap<String, ArrayList<String>>();
	}
}
