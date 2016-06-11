import java.io.Serializable;

public class Message implements Serializable{	
	String dst_addr;	
	int dst_port;
	String src_addr;	
	int src_port;	
	String type;
	byte[] msg;
	
	public Message(String d_a, int d_p, String s_a, int s_p, String t, byte[] m){
		dst_addr = d_a;
		dst_port = d_p;
		src_addr = s_a;
		src_port = s_p;		
		type = t;
		msg = m;
	}
}
