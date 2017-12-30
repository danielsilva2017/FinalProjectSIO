import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.Scanner;

import com.google.gson.*;

public class ClientActions {
	
	private ClientEncryption en;
	private Socket server;
	private BufferedReader in;
	private PrintWriter out;
	private JsonObject reply = null;
	private JsonParser parser;
	private int id;
	
	public ClientActions(Socket s) {
		try {
			this.en = new ClientEncryption("RSA");
			this.server = s;
			this.in = new BufferedReader(new InputStreamReader(this.server.getInputStream()));
			this.out = new PrintWriter(this.server.getOutputStream(), true);
			this.parser = new JsonParser();
		} catch (IOException e) {
			System.out.println("Failed to instantiate client.\n"+e);
			System.exit(1);
		}
	}
	
	public int getID() {
		return this.id;
	}
	
	private void awaitLoginInfo() throws IOException {
		String r = in.readLine();
		this.reply = this.parser.parse(r).getAsJsonObject();
		String type = this.reply.get("type").getAsString();
		if (!type.equals("login"))
			System.out.println("Warning: expected reply to \"login\", got \""+type+"\"");
	}
	
	private void sendLoginInfo(String msg) {
		out.println(msg);
	}
	
	private void awaitReply(String t) throws IOException {
		String r = in.readLine();
		this.reply = this.parser.parse(en.validateMessage(r)).getAsJsonObject();
		String type = this.reply.get("type").getAsString();
		if (!type.equals(t))
			System.out.println("Warning: expected reply to \""+t+"\", got \""+type+"\"");
		if (this.reply.has("error")) {
			String error = this.reply.get("error").getAsString();
			System.out.println("An error occurred on \""+t+"\": "+error+".");
		}
	}
	
	private void send(String msg) { //encrypts with ccpriv too
		out.println(en.authenticateMessage(msg));
	}
	
	
	@SuppressWarnings("resource")
	public void login(String alg) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {	
		String msg = "{\"type\":\"login\","
				 +"\"alg\":\""+"RSA"+"\","
				 +"\"skey\":\""+en.getSessionKey()+"\","
				 +"\"cckey\":\""+en.getSignatureKey()+"\","
				 +"\"uuid\":\""+en.generateDigest()+"\""
				 +"}";
		sendLoginInfo(msg);
		awaitLoginInfo();
		String tpub = this.reply.get("result").getAsString();
		en.setExtPublicKey(tpub);
		
		int id = this.reply.get("exists").getAsInt();
		
		if (!alg.equals("RSA")) loginSym(alg);
		
		Scanner sc = new Scanner(System.in);

		if (id!=-1) { //exists
			this.id = id;
			System.out.print("Please enter your password:\n> ");
			String pw = sc.nextLine();
			while (!checkPassword(pw)) {
				System.out.print("Please enter your password:\n> ");
				pw = sc.nextLine();
			}			
			String[] credentials = getMyCredentials();
			en.recoverExtraKeys(credentials[2], credentials[3], credentials[4]);

		} else { //new
			System.out.println("You do not yet have an account, and it will now be created.");
			System.out.print("Username: ");
			String u = sc.nextLine();
			System.out.print("Password: ");
			String p = sc.nextLine();
			create(u,p);
		}
		
	}
	
	private void loginSym(String alg) throws IOException {
		en.generateSymKeys(alg);
		
		String msg = "{\"type\":\"sym\","
				 +"\"alg\":\""+en.encryptMessage(alg)+"\","
				 +"\"ekey\":\""+en.encryptMessage(en.getEncryptSessionKey())+"\","
				 +"\"akey\":\""+en.encryptMessage(en.getAuthSessionKey())+"\""
				 +"}";
		send(msg);
		awaitReply("sym");
		if (this.reply.has("result")) {
			en.setAlg(alg);
		}
	}
	
	private void create(String username, String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		en.setPassword(password);
		String digest = en.generateDigest();
		en.generateExtraKeys();
		
		String msg = "{\"type\":\"create\","
					+"\"uuid\":\""+en.encryptMessage(digest)+"\","
					+"\"cckey\":\""+en.encryptMessage(en.getSignatureKey())+"\","
					+"\"ccalg\":\""+en.encryptMessage(en.getCitizenCardAlg())+"\","
					+"\"sign\":\""+en.encryptMessage(en.signMessage(digest))+"\","
					+"\"user\":\""+en.encryptMessage(username)+"\","
					+"\"e\":\""+en.encryptMessage("RSA")+"\","
					+"\"epb\":\""+en.encryptMessage(en.get2ndPublicKey())+"\","
					+"\"epv\":\""+en.encryptMessage(en.getEncrypted2ndPrivateKey())+"\""
					+"}";
		send(msg);
		awaitReply("create");
		if (this.reply.has("result")) {
			String id = this.reply.get("result").getAsString();
			this.id = Integer.parseInt(en.decryptMessage(id));
			System.out.println("Successfully registered.");
		}	
	}
	
	public void list() throws IOException {
		list(0);
	}
	
	public void listMe() throws IOException {
		list(this.id);
	}
	
	public String[] getMyCredentials() throws IOException { //[ccalg, cckey, extraalg, extrapub, extrapriv]
		return getCredentials(this.id);
	}
	
	public boolean checkPassword(String p) throws IOException {
		String msg = "{\"type\":\"list\"";
		
		if (id==0) //all
			return false;
		
		msg+=",\"id\":\""+en.encryptMessage(String.valueOf(this.id))+"\"";	
		msg+="}";
		
		send(msg);
		awaitReply("list");
		if (this.reply.has("result")) {
			String enc = en.decryptMessage(this.reply.get("result").getAsString());
			JsonArray list = this.parser.parse(enc).getAsJsonArray();
			for (JsonElement e: list) {
				String pw = e.getAsJsonObject().get("epv").getAsString();
				return en.testRecovery(p, pw);
			}
		}
		
		return false;
	}
	
	public String[] getCredentials(Integer id) throws IOException { //[ccalg, cckey, extraalg, extrapub, extrapriv(?)]
		String msg = "{\"type\":\"list\"";
		
		if (id==0) //all
			return null;
		
		msg+=",\"id\":\""+en.encryptMessage(id.toString())+"\"";	
		msg+="}";

		send(msg);
		awaitReply("list");
		if (this.reply.has("result")) {
			String enc = en.decryptMessage(this.reply.get("result").getAsString());
			JsonArray list = this.parser.parse(enc).getAsJsonArray();
			for (JsonElement e: list) {
				if (id==this.id) {
					String[] res = {e.getAsJsonObject().get("ccalg").getAsString(), 
							e.getAsJsonObject().get("cckey").getAsString(),
							e.getAsJsonObject().get("e").getAsString(),
							e.getAsJsonObject().get("epb").getAsString(),
							e.getAsJsonObject().get("epv").getAsString()
							};
					return res;
				} else {
					String[] res = {e.getAsJsonObject().get("ccalg").getAsString(), 
							e.getAsJsonObject().get("cckey").getAsString(),
							e.getAsJsonObject().get("e").getAsString(),
							e.getAsJsonObject().get("epb").getAsString()
							};
					return res;
				}
			}
		}
		
		return null;
	}
	
	public void list(Integer id) throws IOException {
		String msg = "{\"type\":\"list\"";
		
		if (id!=0) //not self id
			msg+=",\"id\":\""+en.encryptMessage(id.toString())+"\"";
		
		msg+="}";
		
		send(msg);
		awaitReply("list");
		if (this.reply.has("result")) {
			String enc = en.decryptMessage(this.reply.get("result").getAsString());
			JsonArray list = this.parser.parse(enc).getAsJsonArray();
			for (JsonElement e: list) {
				int theirid = e.getAsJsonObject().get("id").getAsInt();
				String name = e.getAsJsonObject().get("user").getAsString();
				System.out.print(theirid+" - "+name);
				if (theirid==this.id) System.out.print(" (you)");
				System.out.println();
			}
		}
	}
	
	public void mnew(Integer id) throws IOException {
		String msg = "{\"type\":\"new\",\"id\":\""+en.encryptMessage(id.toString())+"\"}";
		send(msg);
		awaitReply("new");
		if (this.reply.has("result")) {
			String enc = en.decryptMessage(this.reply.get("result").getAsString());
			JsonArray list = this.parser.parse(enc).getAsJsonArray();
			if (list.size()==0) System.out.println("You have no unread messages.");
			else System.out.println("You have the following unread messages:");
			for (JsonElement elem: list)
				System.out.println(elem.getAsString());
		}
	}
	
	public void all(Integer id) throws IOException {
		String msg = "{\"type\":\"all\",\"id\":\""+en.encryptMessage(id.toString())+"\"}";

		send(msg);
		awaitReply("all");
		if (this.reply.has("result")) {
			JsonArray array = this.reply.get("result").getAsJsonArray();
			
			String userallstring = en.decryptMessage(array.get(0).getAsString());
			String usersentstring = en.decryptMessage(array.get(1).getAsString());
			JsonArray userall = this.parser.parse(userallstring).getAsJsonArray();
			JsonArray usersent = this.parser.parse(usersentstring).getAsJsonArray();
			if (userall.size()==0) System.out.println("You have received no messages.");
			else System.out.println("You have received the following messages:");
			for (JsonElement e: userall)
				System.out.println(e.getAsString());
			if (usersent.size()==0) System.out.println("And have sent no messages.");
			else System.out.println("And have sent the following messages:");
			for (JsonElement e: usersent)
				System.out.println(e.getAsString());
		}
	}
	
	public void send(Integer source, Integer rdest, String msgbody) throws IOException {
		
		String[] credentials = getCredentials(rdest);
		
		if (credentials==null) {
			System.out.println("Command \"send\" failed to get user "+rdest+"'s information.");
			return;
		}
		
		String encryptedBody = en.encryptWithSpecificKey(credentials[2], credentials[3], msgbody);
		String encryptedCopy = en.encryptMessageCopy(msgbody);
		String signature = en.signMessage(msgbody);
		
		String msg = "{\"type\":\"send\","
					 +"\"src\":\""+en.encryptMessage(source.toString())+"\","
					 +"\"dst\":\""+en.encryptMessage(rdest.toString())+"\","
					 +"\"msg\":\""+en.encryptMessage(encryptedBody)+"\","
					 +"\"copy\":\""+en.encryptMessage(encryptedCopy)+"\","
					 +"\"sign\":\""+en.encryptMessage(signature)+"\""
					 +"}";

		send(msg);
		awaitReply("send");
		if (this.reply.has("result")) {
			String enc = en.decryptMessage(this.reply.get("result").getAsString());
			JsonArray array = this.parser.parse(enc).getAsJsonArray();			
			String msgid = array.get(0).getAsString();
			String receiptid = array.get(1).getAsString();
			System.out.println("Your message ("+msgid+") has been sent.");
			System.out.println("This is the receipt's ID: "+receiptid);
		}
	}

	public void recv(Integer userid, String msgid) throws IOException {
		String msg = "{\"type\":\"recv\",\"id\":\""+en.encryptMessage(userid.toString())
				+"\",\"msg\":\""+en.encryptMessage(msgid)+"\"}";

		send(msg);
		awaitReply("recv");
		if (this.reply.has("result")) {
			String enc = en.decryptMessage(this.reply.get("result").getAsString());
			JsonArray array = this.parser.parse(enc).getAsJsonArray();
			
			int senderid = array.get(0).getAsInt();
			String recvmsg = array.get(1).getAsString();
			String recvsign = array.get(2).getAsString();
			
			//validate sender's signature on that message
			String[] credentials = getCredentials(senderid);
			
			if (credentials==null) {
				System.out.println("Command \"recv\" failed to get user "+senderid+"'s information.");
				return;
			}
			
			String plaintext = en.decryptWith2ndPrivate(recvmsg);
			
			if (en.verifySign(credentials[0], credentials[1], plaintext, recvsign)) {
				System.out.println("This is the content of message "+msgid+", sent by ID "+senderid+":");
				System.out.println(plaintext);
				receipt(userid, msgid, plaintext);
			} else {
				System.out.println("Sender's signature was not correctly validated (\"recv\").");
			}
		}
	}
	
	private void receipt(Integer userid, String msgid, String msgplain) throws IOException {		
		String receipt = en.signMessage(msgplain);
				
		String msg = "{\"type\":\"receipt\","
					 +"\"id\":\""+en.encryptMessage(userid.toString())+"\","
					 +"\"msg\":\""+en.encryptMessage(msgid)+"\","
					 +"\"receipt\":\""+en.encryptMessage(receipt)+"\""
					 +"}";
		send(msg);
	}
	
	public void status(Integer userid, String msgid) throws IOException {		
		String msg = "{\"type\":\"status\","
					 +"\"id\":\""+en.encryptMessage(userid.toString())+"\","
					 +"\"msg\":\""+en.encryptMessage(msgid)+"\""
					 +"}";

		send(msg);
		awaitReply("status");
		if (this.reply.has("result")) {
			String enc = en.decryptMessage(this.reply.get("result").getAsString());
			JsonObject data = this.parser.parse(enc).getAsJsonObject();
			
			String m = en.decryptMessageCopy(data.get("msg").getAsString());
			
			System.out.println("Checking message "+msgid+", containing the text:");
			System.out.println(m+"\n");
			
			JsonArray receipts = data.get("receipts").getAsJsonArray();
			
			if (receipts.size()==0) System.out.println("This message has not yet been read.");
			else System.out.println("This message was read at:");
			
			for (JsonElement e: receipts) {
				JsonObject o = e.getAsJsonObject();
				String sign = o.get("receipt").getAsString();
				int senderid = o.get("id").getAsInt();
				long d = o.get("date").getAsLong();
				Date date =new Date(d);
				
				//validate sender's signature on that message
				String[] credentials = getCredentials(senderid);
				
				if (credentials==null) {
					System.out.println("Command \"recv\" failed to get user "+senderid+"'s information.");
				}
				
				if (credentials !=null && en.verifySign(credentials[0], credentials[1], m, sign)) {
					System.out.println(date);
				}
			}
		}
	}

}
