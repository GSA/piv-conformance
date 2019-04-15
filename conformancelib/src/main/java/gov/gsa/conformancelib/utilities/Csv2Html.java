package gov.gsa.conformancelib.utilities;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Csv2Html {
    private static final Logger s_logger = LoggerFactory.getLogger(Csv2Html.class);

	public static String escapeChars(String lineIn) {
		StringBuilder sb = new StringBuilder();
		int lineLength = lineIn.length();
		for (int i = 0; i < lineLength; i++) {
			char c = lineIn.charAt(i);
			switch (c) {
			case '"': 
				sb.append("&quot;");
				break;
			case '&':
				sb.append("&amp;");
				break;
			case '\'':
				sb.append("&apos;");
				break;
			case '<':
				sb.append("&lt;");
				break;
			case '>':
				sb.append("&gt;");
				break;
			default: sb.append(c);
			}
		}
		return sb.toString();
	}

	public static void tableHeader(PrintStream ps, String[] columns) {
		ps.print("<tr>");
		for (int i = 0; i < columns.length; i++) {
			String innerHtml = columns[i].replaceAll("^&quot;|&quot;$", "");
			ps.print("<th>");
			ps.print(innerHtml);
			ps.print("</th>");
		}
		ps.println("</tr>");
	}

	public static void tableRow(PrintStream ps, String[] columns) {
		ps.print("<tr>");

		for (int i = 0; i < columns.length; i++) {
			String innerHtml = columns[i].replaceAll("^&quot;|&quot;$", "");
			if (innerHtml.contentEquals("Fail")) {
				ps.print("<td class=\"fail\">");
			} else if (innerHtml.contentEquals("Pass")) {
				ps.print("<td class=\"pass\">");
			} else {
				ps.print("<td>");
			}
			ps.print(innerHtml);
			ps.print("</td>");
		}
		ps.println("</tr>");
	}
	
	public static void generateHtml(String sourceFileName, PrintStream destination, boolean withTableHeader) {
		ClassLoader classLoader = ClassLoader.getSystemClassLoader();
		 
		File file = new File(sourceFileName);

		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(file));
		} catch (FileNotFoundException e1) {
			s_logger.error("No such file: {}", sourceFileName);
			// XXX *** THROW
			return;
		} 
		
		destination.println("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">");
		destination.println("<html xmlns=\"http://www.w3.org/1999/xhtml\">");
		destination.println("<head><meta http-equiv=\"Content-type\" content=\"text/html;charset=UTF-8\"/>");
		destination.println("<title>Test Results</title>");
		destination.println("<style type=\"text/css\">");
		destination.println("body{background-color:#FFF;color:#000;font-family:OpenSans,sans-serif;font-size:10px;}");
		destination.println("body{background-color:#FFF;color:#000;font-family:OpenSans,sans-serif;font-size:10px}");
		destination.println("table{border:0.2em solid #2F6FAB;border-collapse:collapse}");
		destination.println("th{border:0.15em solid #2F6FAB;padding:0.5em;background-color:#E9E9E9}");
		destination.println("td{border:0.1em solid #2F6FAB;padding:0.5em;background-color:#FFFFFF}");
		destination.println("td.pass{border:0.1em solid #2F6FAB;padding:0.5em;background-color:green;color:black}");
		destination.println("td.fail{border:0.1em solid #2F6FAB;padding:0.5em;background-color:red;color:yellow}</style>");
		destination.println("</head><body><h1>Test Results</h1>");

		destination.println("<table>");
		String stdinLine;
		boolean firstLine = true;
		
		try {
			CSVParser csvParser = new CSVParser(br, CSVFormat.DEFAULT);
			for(CSVRecord r : csvParser) {
				String[] columns = { escapeChars(r.get(0)), escapeChars(r.get(1)), escapeChars(r.get(2)),
						escapeChars(r.get(3)), escapeChars(r.get(4))};
				if (withTableHeader == true && firstLine == true) {
					tableHeader(destination, columns);
					firstLine = false;
				} else {
					tableRow(destination, columns);
				}
			}
			csvParser.close();
			br.close();
		} catch (IOException e) {
			s_logger.error("Caught exception while writing html", e);
			// XXX *** THROW
			return;
		}
		destination.println("</table></body></html>");
	}

	public static void main(String[] args) throws Exception {
		
		if (args.length == 0) {
			System.out.println ("Usage: Csv2Html <filename> [header]\n");
		}
		
		String filename = (args[0]);
		boolean withTableHeader = (args.length > 1);
		generateHtml(filename, System.out, withTableHeader);
	}
		
}
