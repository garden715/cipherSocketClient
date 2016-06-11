import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class ClientMain {
	public static void main(String[] args) throws Exception{
		Scanner scan = new Scanner(System.in);
		
		String server_addr;
		int server_port;
		String client_addr;
		int client_port;
		String gateway_addr;
		int gatewayInterface = 3000;
		
		/* RSA 키 생성 후 저장 */
		Key[] rsaKey = generateRSAKey();
		Key publicKey = rsaKey[0];
		Key privateKey = rsaKey[1];
		
		System.out.println("=======Input The Information=======");
		System.out.print("Server IP : ");
		server_addr = scan.nextLine();
		
		System.out.print("Server Port : ");
		server_port = Integer.parseInt(scan.nextLine());
				
		System.out.print("Gateway IP : ");
		gateway_addr = scan.nextLine();
		
		/*connect*/		
		Socket socket = new Socket(gateway_addr,gatewayInterface);		
		ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());				
		ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
		
		/* Client ip, port 정보 */
		client_addr = socket.getLocalAddress().toString();
		client_port = socket.getLocalPort();
		
		/* connect message 생성
		 * Server IP, Server Port, Client IP, Client Port, Message Type, RSA PublicKey */
		System.out.println("\nConnect message");
		Message send_message = new Message(server_addr,server_port, client_addr, client_port, "connect", publicKey.getEncoded());	
		oos.reset();
		oos.writeObject(send_message); /* message 전송 */
		
		/* 응답 기다림 
		 * 응답 내용은 AES Key를 public key로 암호화한 byte 배열 */
		Message connect_message = (Message)ois.readObject();
		
		/* connect에 대한 응답 메시지의 데이터를 private 키로 복호화 */
		Key cipherKey = new SecretKeySpec(testRSA_decrypt(privateKey, connect_message.msg), "AES");
		System.out.println("AES Key>"+byteArrayToHex(cipherKey.getEncoded()));
		
		System.out.print("Send Data (>\"exit\" => disconnect)");
		
		/*send data*/
		while(true){
			System.out.print(">");
			String str = scan.nextLine();
			if(str.equals("exit")) break;
			
			/* 이후 텍스트(데이터)는 교환된 대칭키를 사용하여 암호화 */
			byte[] cipherText = testAES128_encrypt(cipherKey,str);	
			send_message = new Message(server_addr,server_port,client_addr, client_port,"data",cipherText);
			oos.reset();
			oos.writeObject(send_message);
			
			Message recv_message = (Message)ois.readObject();
			System.out.println(">"+new String(testAES128_decrypt(cipherKey,recv_message.msg)));
		}
		
		/* disconnect message 생성
		 * Type 을 disconnect 로 설정 */
		send_message = new Message(server_addr,server_port,client_addr, client_port,"disconnect",null);
		oos.reset();
		oos.writeObject(send_message);
		
		/* 5초 후 socket close*/
		for(int i=0;i<5;i++){
			System.out.println("wait "+(5-i));
			Thread.sleep(1000);
		}
		ois.close();
		socket.close();
		System.out.println("disconnect ");
	}
	
	/* AES 암호화 */
	public static byte[] testAES128_encrypt(Key key, String text){
		byte[] cipherText = null;		
		
		try{
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipherText = cipher.doFinal(text.getBytes());
		}catch(Exception e){
			e.printStackTrace();
		}
		return cipherText;
	}
	
	/* AES 복호화 */
	public static byte[] testAES128_decrypt(Key key, byte[] cipherText){
		byte[] plainText = null;
		try{
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, key);
			plainText = cipher.doFinal(cipherText);
		}catch(Exception e){
			e.printStackTrace();
		}
		return plainText;
	}
	
	/* RSA 암호화 */
	public static byte[] testRSA_encrypt(Key key, String text) throws Exception{
		Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(text.getBytes()); // 암호화된 데이터(byte 배열)
        return cipherText;
	}
	
	/* RSA 복호화 */
	public static byte[] testRSA_decrypt(Key key, byte[] cipherText) throws Exception{
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = cipher.doFinal(cipherText);
        return plainText;
	}
	
	/* RSA key 생성 */
	public static Key[] generateRSAKey() throws Exception{
		Key[] key = new Key[2];
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        Key publicKey = keyPair.getPublic(); // 공개키
        Key privateKey = keyPair.getPrivate(); // 개인키
        
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
        RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
        
        System.out.println("=======RSA Key generate=======");
        System.out.println("public key modulus(" + publicKeySpec.getModulus() + 
        		") exponent(" + publicKeySpec.getPublicExponent() + ")");
        System.out.println("private key modulus(" + privateKeySpec.getModulus() + 
        		") exponent(" + privateKeySpec.getPrivateExponent() + ")");
        
        key[0] = publicKey;
        key[1] = privateKey;
        
        return key;
	}
	
	/* byte 배열을 hex string으로 변환해 주는 함수 */
	public static String byteArrayToHex(byte[] ba) {
	    if (ba == null || ba.length == 0) {
	        return null;
	    }
	 
	    StringBuffer sb = new StringBuffer(ba.length * 2);
	    String hexNumber;
	    for (int x = 0; x < ba.length; x++) {
	        hexNumber = "0" + Integer.toHexString(0xff & ba[x]);
	 
	        sb.append(hexNumber.substring(hexNumber.length() - 2));
	    }
	    return sb.toString();
	} 
}
