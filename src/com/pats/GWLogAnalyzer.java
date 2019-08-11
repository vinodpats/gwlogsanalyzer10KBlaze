//Author: Pats Corporation (Vinod Patil)
//Date:  July 2019
//License: GNU General Public License v3.0

package com.pats;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Scanner;

public class GWLogAnalyzer {

	public static void main(String[] args) {
		System.out.println("** This utility has been developed by Pats Corporation (Vinod Patil). ** \n\n Use it with caution to generate secinfo and reginfo files \n\n");
		
		Scanner scan = new Scanner(System.in);
		System.out.println("Provide Logs directory (e.g. c:\\gwlogs): ");
		String filePath = scan.nextLine();
		
		Path path;
		String regRule = "", secRule = "";
		HashSet<String> regSet = new HashSet<String>();
		HashSet<String> secSet = new HashSet<String>();
		Charset charset = Charset.forName("UTF-8");

		
		try {
			File folder = new File(filePath);
			File[] listOfFiles = folder.listFiles();
			for (File file : listOfFiles) {
				System.out.println("Processing file "+file.getName());
				
				path = Paths.get(file.getAbsolutePath());
				BufferedReader reader = Files.newBufferedReader(path, charset);
				String line = null;
				while ((line = reader.readLine()) != null) {
					//reginfo
					if (line.contains("reginfo (no rule found")) {
						regRule = "";
						int tpBegin = line.indexOf("TP=");
						int hostBegin = line.indexOf("HOST=");
						String host = line.substring(hostBegin, line.length());
						int ipAddressBegin = host.indexOf(" (");

						regRule = "P TP=" + line.substring(tpBegin + 3, hostBegin - 2) + " HOST=" + host.substring(5, ipAddressBegin) + " CANCEL="
								+ host.substring(5, ipAddressBegin)+ ",internal,local ACCESS="+host.substring(5, ipAddressBegin) +",internal,local";
						regSet.add(regRule);

					} 
					
					//secinfo
					else if (line.contains("secinfo (no rule found")) {
						secRule = "";
						int tpBegin = line.indexOf("TP=");
						int userBegin = line.indexOf("USER=");
						int userHostBegin = line.indexOf("USER-HOST=");
						int hostBegin = line.indexOf(", HOST=");

						String userHost = line.substring(userHostBegin, hostBegin);
						int userHostIPAddressBegin = userHost.indexOf(" (");

						String host = line.substring(hostBegin, tpBegin - 2);
						int hostIPAddressBegin = host.indexOf(" (");

						secRule = "P USER="
								+ line.substring(userBegin + 5, userHostBegin - 2) + " USER-HOST="
								+ userHost.substring(10, userHostIPAddressBegin) + " HOST="
								+ host.substring(7, hostIPAddressBegin)+" TP=" + line.substring(tpBegin + 3, line.length());
						secSet.add(secRule);

					} // end secinfo

				} // end of file
				reader.close();

			} // end of directory

			// now save result
			// ************************Reginfo**********************"
			Path reginfo = Paths.get("reginfo");
			BufferedWriter writer = Files.newBufferedWriter(reginfo, charset);
			Iterator<String> it = regSet.iterator();
			writer.write("#VERSION=2");
			writer.newLine();
			while (it.hasNext()) {
				writer.write(it.next());
				writer.newLine();

			}
			writer.write("#last line of reg_info");
			writer.newLine();
			writer.write("P TP=* HOST=internal,local CANCEL=internal,local ACCESS=internal,local");

			writer.flush();
			writer.close();
			
			System.out.println("reginfo generated successfully");
			// "************************Secinfo**********************");

			Path secinfo = Paths.get("secinfo");
			writer = Files.newBufferedWriter(secinfo, charset);
			it = secSet.iterator();
			writer.write("#VERSION=2");
			writer.newLine();
			while (it.hasNext()) {
				writer.write(it.next());
				writer.newLine();
			}
			writer.write("#last line of sec_info");
			writer.newLine();
			writer.write("P USER=* USER-HOST=internal,local HOST=internal,local TP=*");
			
			writer.flush();
			writer.close();
			System.out.println("secinfo generated successfully");
			scan.close();
			
			
		} catch (IOException x) {
			System.err.format("Error- "+ x.getMessage());
		} catch(NullPointerException x) {
			System.err.format("Error- Check if specified path is directory and it exists "+ x.getMessage());
		}

	}

}