/* for device listing */
import java.util.Arrays;
import java.util.ArrayList;  
import java.util.Date;  
import java.util.List;
import java.util.*;
import java.text.*;  

/* PCap */  
import org.jnetpcap.Pcap;  
import org.jnetpcap.PcapIf;  
import org.jnetpcap.packet.PcapPacket;  
import org.jnetpcap.packet.PcapPacketHandler;  

/* Protocols */ 
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.vpn.L2TP;
import org.jnetpcap.protocol.wan.PPP;
import org.jnetpcap.protocol.application.Html;
import org.jnetpcap.protocol.application.WebImage;
import org.jnetpcap.protocol.voip.Rtp;
import org.jnetpcap.protocol.voip.Sdp;
import org.jnetpcap.protocol.voip.Sip;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.lan.IEEE802dot1q;
import org.jnetpcap.protocol.lan.IEEE802dot2;
import org.jnetpcap.protocol.lan.IEEE802dot3;
import org.jnetpcap.protocol.lan.IEEESnap;
import org.jnetpcap.protocol.lan.SLL;

import org.jnetpcap.protocol.application.Html;

/* HTTP Requests */
import org.jnetpcap.protocol.tcpip.Http.ContentType;  
import org.jnetpcap.protocol.tcpip.Http.Request;  
import org.jnetpcap.protocol.tcpip.Http.Response;

/* FormatUtils */
import org.jnetpcap.packet.format.FormatUtils;

/* GZIP */
import java.io.*;
import java.io.BufferedReader;
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

public static Ethernet eth = new Ethernet();
public static Arp arp = new Arp();
public static Icmp icmp = new Icmp();
public static Ip4 ip = new Ip4();
public static Tcp tcp = new Tcp();
public static Udp udp = new Udp();
public static Http http = new Http(); 

/* What to sniff */
public static int sniffEth = 0;
public static int sniffArp = 0;
public static int sniffIcmp = 0;
public static int sniffIp = 0;
public static int sniffTcp = 0;
public static int sniffUdp = 0;
public static int sniffHttp = 1;

/* variables */
public static byte[] mymac = new byte[5];
public static InetAddress inet;
public static Enumeration e;
public static NetworkInterface n;
public static Enumeration ee;

    public static void main(String[] args) { 
        
        /* Print welcome message */
        System.out.println(
        "\n[***] Support: manuel.zarat@gmail.com\n" +
        "\n[***] Dieses Programm dient ausschlieﬂlich Lernzwecken.\n" +
        "[***] Absolut keine Garantie, daher Nutzung auf eigene Gefahr.\n" + 
        "[***] Bitte beachten Sie die jeweils geltenden Gesetze!!!\n");    
        
        List<PcapIf> alldevs = new ArrayList<PcapIf>();
        StringBuilder errbuf = new StringBuilder();  
                
        int interfaces = Pcap.findAllDevs(alldevs, errbuf);
    
        try {           
                
            e = NetworkInterface.getNetworkInterfaces();
            while (e.hasMoreElements()) {
                
                n = (NetworkInterface)e.nextElement();                                      
                ee = n.getInetAddresses();
                    
                if (ee.hasMoreElements()) {
                    
                    System.out.println("\n\n"+n.getDisplayName());
                    try { System.out.println(asString(n.getHardwareAddress())); }catch(Exception e) {}
                        
                }
                        
                while (ee.hasMoreElements()) {
                                    
                    InetAddress ninet = (InetAddress)ee.nextElement();
                        
                    if(null != ninet) {
                                                  
                        //System.out.println("\n\n"+n.getDisplayName());
                        System.out.println(ninet);
                                                  
                    }
                        
                }
                                		
            }
                    
            System.out.println("\n\n");
                
        }catch(Exception see) {}
    
               
        int i = 0;
        for (PcapIf device : alldevs) {
                   
            String description = (device.getDescription() != null) ? device.getDescription() : "keine Beschreibung";
        
            try {
                
                System.out.println("[***] #"+(i++)+": "+description+" :: " + asString(device.getHardwareAddress())); 
                                       
            }catch(Exception e) {} 
                   
        }
                 
        if (interfaces == Pcap.NOT_OK || alldevs.isEmpty()) {
                
            System.out.println("[!!!] Konnte Interfaces nicht auslesen: " + errbuf.toString() + "\n");  
            return; 
                
        }
       
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("\n[***] Welches Interface soll genutzt werden?: ");
        String eingabe = "";
        try  { eingabe = br.readLine(); } catch (IOException ioe) {}
               
        PcapIf device = alldevs.get(new Integer(eingabe));
               
        System.out.print("\n");  
       
        int snaplen = 64 * 1024;           // full packets >=64 bytes /truncated/gzipped?
        int flags = Pcap.MODE_PROMISCUOUS; // all packets  
        int timeout = 10 * 1000;  
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
      
        if (pcap == null) {  
            
            System.err.printf("[!!!] Error opening interface: " + errbuf.toString());  
            return; 
                 
        } 
            
        /* lets go */ 
        Date dNow = new Date( );
        SimpleDateFormat ft = new SimpleDateFormat ("yyyy.MM.dd 'at' hh:mm:ss");  
        print("[***] Start scan: " + ft.format(dNow));
     
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {  
      
            public void nextPacket(PcapPacket packet, String user) {  
                    
                //print("\n*****************************");
                //print("*** Paket #" + packet.getFrameNumber() + " abgefangen ***");
                //print("*****************************\n");
                    
                if(packet.hasHeader(eth) && sniffEth == 1) {
                    
                    print("[ETH] SRC: " + FormatUtils.mac(eth.source()));
                    print("[ETH] DST: " + FormatUtils.mac(eth.destination()));
                    print("\n");
                        
                }
                    
                if (packet.hasHeader(arp) && sniffArp == 1) {
                        
                    print("[***] ARP");
                    //print("[ARP] SHA: " + arp.sha());
                    //print("[ARP] THA: " + arp.tha());
                    //print("[ARP] FRAME_NO: " + packet.getFrameNumber());
                    //print("[ARP] SRC: " + FormatUtils.mac(arp.Source()));
                        
                    String sourceMac = FormatUtils.mac(eth.source());
                    String destinationMac = FormatUtils.mac(eth.destination());
                        
                    print("[ARP] SHA: " + sourceMac);
                    print("[ARP] THA:" + destinationMac);
                    print("\n");
                        
                }
                    
                if (packet.hasHeader(icmp) && sniffIcmp == 1) {
                        
                    print("[***] ICMP");
                    print("\n");
                        
                }
                    
                if(packet.hasHeader(ip) && sniffIp == 1) {
                    
                    print("[IP] SRC: " + FormatUtils.ip(ip.source()));
                    print("[IP] DST: " + FormatUtils.ip(ip.destination()));
                    print("\n");
                      
                }
    
                if(packet.hasHeader(tcp) && sniffTcp == 1) {
                    
                    print("[TCP] SRC: " + tcp.source());
                    print("[TCP] DST: " + tcp.destination());
                    print("\n");
                        
                }
    
                if(packet.hasHeader(udp) && sniffUdp == 1) {
                    
                    print("[UDP] SRC: " + udp.source());
                    print("[UDP] DST: " + udp.destination());
                    print("\n");
                        
                }
                    
                if(packet.hasHeader(http) && sniffHttp == 1) {
    
                    //if(http.hasPayload()){
                        
                        print("[***] HTTP");
                        print("[HTTP] payload length: " + http.getPayloadLength());
                        //print("[HTTP] truncated: " + http.isPayloadTruncated());
                        print(packet.toHexdump());
    
                    //}
                        
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
             
    } 
    
    private static String macAsString(final byte[] mac) { 
         
        final StringBuilder buf = new StringBuilder();
              
        for(byte b : mac) { 
             
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
    
    private static String decompress(byte[] html) {
        
        /* */
        String output = "";
            
        try {
            
            GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(html));
            BufferedReader br = new BufferedReader(new InputStreamReader(gzip));
            String tmp = "";
                
            while(null != br.readLine()) {
                
                output += br.readLine();
                
            }
            
        }catch(IOException ioe) {}
            
        return output;
        
    }
    
    public static void print(String out) {
        
        System.out.println(out);    
        
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

}