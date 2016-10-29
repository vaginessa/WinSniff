import java.net.URL;
import java.net.URLConnection;

import java.lang.StringBuffer;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.BufferedWriter;
import java.io.FileWriter;

public class HTTP_GET_REQUEST {
	
	public static void main(String[] args) throws Exception {
		
		URL url = new URL(args[0]);
	    URLConnection conn = url.openConnection();

	    // Set the cookie value to send
      String cookies = args[1];
	    conn.setRequestProperty("Cookie", cookies);

	    // Send the request to the server
	    conn.connect();
      
        // Get the response
        StringBuffer answer = new StringBuffer();
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            answer.append(line);
        }
        reader.close();
        System.out.println(answer.toString());
/*        
FileWriter fw = new FileWriter("ausgabe.txt");
BufferedWriter bw = new BufferedWriter(fw);

bw.write(answer.toString());

bw.close();
*/		
	}

}