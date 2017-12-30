import java.lang.Thread;
import java.net.Socket;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import com.google.gson.*;

class ServerActions implements Runnable {

	boolean registered = false;

	Socket client;
	BufferedReader in;
	String m;
	OutputStream out;
	ServerControl registry;
	ServerEncryption en;

	ServerActions(Socket c, ServerControl r) {
		client = c;
		registry = r;
		en = new ServerEncryption();

		try {
			this.in = new BufferedReader(new InputStreamReader(c.getInputStream()));
			this.out = c.getOutputStream();
		} catch (Exception e) {
			System.err.print("Cannot use client socket: " + e);
			Thread.currentThread().interrupt();
		}
	}
	
	boolean getMessage() {
		try {
			this.m = in.readLine();
			if (m==null) return false;
			return true;
		} catch (IOException e) {
			System.err.print("Error receiving message from buffer");
			e.printStackTrace();
			System.exit(1);
		}
		return false;
	}

	JsonObject readCommand() {
		try {
			JsonParser parser = new JsonParser();
			if (m.substring(0, 1).equals("{")) {
				JsonElement data = parser.parse(m);
				if (data.isJsonObject()) { //login
					return data.getAsJsonObject();
				}
			} else {
				JsonElement data = parser.parse(en.validateMessage(m));
				if (data.isJsonObject()) { //others
					return data.getAsJsonObject();
				}
			}
			System.err.print(
					"Error while reading command from socket (not a JSON object), connection will be shutdown\n");
			return null;
		} catch (Exception e) {
			System.err.print("Error while reading JSON command from socket, connection will be shutdown\n"+e);
			return null;
		}

	}
	
	void send(String msg) throws IOException { //authenticates and sends to client
		String authmsg = en.authenticateMessage(msg)+"\n";
		out.write(authmsg.getBytes(StandardCharsets.ISO_8859_1));
	}
	
	void sendLoginInfo(String result) { //sends to client
		String msg = "{\"type\":\"login\", ";
		msg += result;
		msg += "}\n";
		try {
			out.write(msg.getBytes(StandardCharsets.ISO_8859_1));
		} catch (Exception e) {
		}
	}

	void sendResult(String type, String result, String error) { //prepares message to send
		String msg = "{\"type\":\""+type+"\", ";

		// Usefull result

		if (result != null) {
			msg += result;
		}

		// error message

		if (error != null) {
			msg += "\"error\":" + error;
		}

		msg += "}\n";

		try {			
			send(msg);
		} catch (Exception e) {
		}
	}

	void executeCommand(JsonObject data) {
		JsonElement cmd = data.get("type");

		if (cmd == null) {
			System.err.println("Invalid command in request: " + data);
			return;
		}
		
		// LOGIN
		
		if (cmd.getAsString().equals("login")) {
			login(data);
		} else
			
		// LOGIN SYM
			
		if (cmd.getAsString().equals("sym")) {
			loginSym(data);
		} else

		// CREATE

		if (cmd.getAsString().equals("create")) {
			create(data);
		} else

		// LIST

		if (cmd.getAsString().equals("list")) {
			list(data);
		} else

		// NEW

		if (cmd.getAsString().equals("new")) {
			mnew(data);
		} else

		// ALL

		if (cmd.getAsString().equals("all")) {
			all(data);
		} else

		// SEND

		if (cmd.getAsString().equals("send")) {
			sendmail(data);
		} else

		// RECV

		if (cmd.getAsString().equals("recv")) {
			recv(data);
		} else

		// RECEIPT

		if (cmd.getAsString().equals("receipt")) {
			receipt(data);
		} else

		// STATUS

		if (cmd.getAsString().equals("status")) {
			status(data);
		} else {

			sendResult("unknown", null, "\"Unknown request\"");
			return;
		
		}
	}
	
	void login(JsonObject data) {
		String tpub = data.get("skey").getAsString();
		String ccpub = data.get("cckey").getAsString();
		String alg = data.get("alg").getAsString();
		String uuid = data.get("uuid").getAsString();
		this.en.setAlg(alg);
		this.en.setExtPublicKey(tpub);
		this.en.setSignatureKey(ccpub);
		this.en.generateKeys();

		sendLoginInfo("\"result\":\"" + en.getSessionKey() + "\", \"exists\":\""+registry.userExistsAndID(uuid)+"\"");
		return;
	}
	
	void loginSym(JsonObject data) {
		String alg = en.decryptMessage(data.get("alg").getAsString());
		String ekey = en.decryptMessage(data.get("ekey").getAsString());
		String akey = en.decryptMessage(data.get("akey").getAsString());				
		sendResult("sym", "\"result\":\""+en.encryptMessage("success")+"\"", null);
		this.en.setAlg(alg);
		this.en.setEncryptionKey(ekey);
		this.en.setAuthKey(akey);
		return;
	}
	
	void create(JsonObject data) {
		String uuid = en.decryptMessage(data.get("uuid").getAsString());
		String ccalg = en.decryptMessage(data.get("ccalg").getAsString());
		String cckey = en.decryptMessage(data.get("cckey").getAsString());
		String sign = en.decryptMessage(data.get("sign").getAsString());
		String user = en.decryptMessage(data.get("user").getAsString());
		String e = en.decryptMessage(data.get("e").getAsString());
		String epb = en.decryptMessage(data.get("epb").getAsString());
		String epv = en.decryptMessage(data.get("epv").getAsString());
		
		data.addProperty("uuid", uuid);
		data.addProperty("ccalg", ccalg);
		data.addProperty("cckey", cckey);
		data.addProperty("sign", sign);
		data.addProperty("user", user);
		data.addProperty("e", e);
		data.addProperty("epb", epb);
		data.addProperty("epv", epv);

		if (uuid == null) {
			System.err.print("No \"uuid\" field in \"create\" request: " + data);
			sendResult("create", null, "\"wrong request format\"");
			return;
		}

		if (registry.userExists(uuid)) {
			System.err.println("User already exists: " + data);
			sendResult("create", null, "\"uuid already exists\"");
			return;
		}

		data.remove("type");
		UserDescription me = registry.addUser(data);

		sendResult("create", "\"result\":\"" + en.encryptMessage(String.valueOf(me.id)) + "\"", null);
		return;
	}
	
	void list(JsonObject data) {
		String list;
		int user = 0; // 0 means all users						
		JsonElement id = data.get("id");

		if (id != null) {
			String uid = en.decryptMessage(data.get("id").getAsString());
			data.addProperty("id", uid);
			JsonElement newid = data.get("id");
			user = newid.getAsInt();
		}



		list = registry.listUsers(user);

		sendResult("list", "\"result\":" + (list == null ? "\""+en.encryptMessage("[]")+"\"" : "\""+en.encryptMessage(list)+"\""), null);
		return;
	}
	
	void mnew(JsonObject data) {
		String uid = en.decryptMessage(data.get("id").getAsString());
		data.addProperty("id", uid);
		JsonElement id = data.get("id");
		int user = id == null ? -1 : id.getAsInt();

		if (id == null || user <= 0) {
			System.err.print("No valid \"id\" field in \"new\" request: " + data);
			sendResult("new", null, "\"wrong request format\"");
			return;
		}
		
		String nm = registry.userNewMessages(user);

		sendResult("new", "\"result\":" + "\""+en.encryptMessage(nm)+"\"", null);
		return;
	}
	
	void all(JsonObject data) {
		String uid = en.decryptMessage(data.get("id").getAsString());
		data.addProperty("id", uid);
		JsonElement id = data.get("id");
		int user = id == null ? -1 : id.getAsInt();

		if (id == null || user <= 0) {
			System.err.print("No valid \"id\" field in \"new\" request: " + data);
			sendResult("all", null, "\"wrong request format\"");
			return;
		}
		
		String am = registry.userAllMessages(user);
		String sm = registry.userSentMessages(user);

		sendResult("all", "\"result\":[" + "\""+en.encryptMessage(am)+"\"" + "," + "\""+en.encryptMessage(sm)+"\"" + "]",
				null);
		return;
	}
	
	void sendmail(JsonObject data) {
		String usrc = en.decryptMessage(data.get("src").getAsString());
		String udst = en.decryptMessage(data.get("dst").getAsString());
		String umsg = en.decryptMessage(data.get("msg").getAsString());
		String ucopy = en.decryptMessage(data.get("copy").getAsString());
		String usign = en.decryptMessage(data.get("sign").getAsString());
		data.addProperty("src", usrc);
		data.addProperty("dst", udst);
		data.addProperty("msg", umsg);
		data.addProperty("copy", ucopy);
		data.addProperty("sign", usign);
		
		JsonElement src = data.get("src");
		JsonElement dst = data.get("dst");
		JsonElement msg = data.get("msg");
		JsonElement copy = data.get("copy");
		JsonElement sign = data.get("sign");

		if (src == null || dst == null || msg == null || copy == null || sign == null) {
			System.err.print("Badly formated \"send\" request: " + data);
			sendResult("send", null, "\"wrong request format\"");
			return;
		}

		int srcId = src.getAsInt();
		int dstId = dst.getAsInt();

		if (registry.userExists(srcId) == false) {
			System.err.print("Unknown source id for \"send\" request: " + data);
			sendResult("send", null, "\"wrong parameters\"");
			return;
		}

		if (registry.userExists(dstId) == false) {
			System.err.print("Unknown destination id for \"send\" request: " + data);
			sendResult("send", null, "\"wrong parameters\"");
			return;
		}

		// Save message and copy

		String response = registry.sendMessage(srcId, dstId, msg.getAsString(), copy.getAsString(), sign.getAsString());

		sendResult("send", "\"result\":" + "\""+en.encryptMessage(response)+"\"", null);
		return;
	}
	
	void recv(JsonObject data) {
		String uid = en.decryptMessage(data.get("id").getAsString());
		String umsg = en.decryptMessage(data.get("msg").getAsString());
		data.addProperty("id", uid);
		data.addProperty("msg", umsg);
		
		JsonElement id = data.get("id");
		JsonElement msg = data.get("msg");

		if (id == null || msg == null) {
			System.err.print("Badly formated \"recv\" request: " + data);
			sendResult("recv", null, "\"wrong request format\"");
			return;
		}

		int fromId = id.getAsInt();

		if (registry.userExists(fromId) == false) {
			System.err.print("Unknown source id for \"recv\" request: " + data);
			sendResult("recv", null, "\"wrong parameters\"");
			return;
		}

		if (registry.messageExists(fromId, msg.getAsString()) == false
				&& registry.messageExists(fromId, "_" + msg.getAsString()) == false) {
			System.err.println("Unknown message for \"recv\" request: " + data);
			sendResult("recv", null, "\"wrong parameters\"");
			return;
		}

		// Read message

		String response = registry.recvMessage(fromId, msg.getAsString());

		sendResult("recv", "\"result\":" + "\""+en.encryptMessage(response)+"\"", null);
		return;
	}
	
	void receipt(JsonObject data) {
		String uid = en.decryptMessage(data.get("id").getAsString());
		String umsg = en.decryptMessage(data.get("msg").getAsString());
		String ur = en.decryptMessage(data.get("receipt").getAsString());
		data.addProperty("id", uid);
		data.addProperty("msg", umsg);
		data.addProperty("receipt", ur);
		
		JsonElement id = data.get("id");
		JsonElement msg = data.get("msg");
		JsonElement receipt = data.get("receipt");

		if (id == null || msg == null || receipt == null) {
			System.err.print("Badly formated \"receipt\" request: " + data);
			sendResult("receipt", null, "\"wrong request format\"");
			return;
		}

		int fromId = id.getAsInt();

		if (registry.messageWasRed(fromId, msg.getAsString()) == false) {
			System.err.print("Unknown, or not yet red, message for \"receipt\" request: " + data);
			sendResult("receipt", null, "\"wrong parameters\"");
			return;
		}

		// Store receipt

		registry.storeReceipt(fromId, msg.getAsString(), receipt.getAsString());
		return;
	}
	
	void status(JsonObject data) {
		String uid = en.decryptMessage(data.get("id").getAsString());
		String umsg = en.decryptMessage(data.get("msg").getAsString());
		data.addProperty("id", uid);
		data.addProperty("msg", umsg);
		
		JsonElement id = data.get("id");
		JsonElement msg = data.get("msg");

		if (id == null || msg == null) {
			System.err.print("Badly formated \"status\" request: " + data);
			sendResult("status", null, "\"wrong request format\"");
			return;
		}

		int fromId = id.getAsInt();

		if (registry.copyExists(fromId, msg.getAsString()) == false) {
			System.err.print("Unknown message for \"status\" request: " + data);
			sendResult("status", null, "\"wrong parameters\"");
			return;
		}

		// Get receipts

		String response = registry.getReceipts(fromId, msg.getAsString());

		sendResult("status", "\"result\":" + "\""+en.encryptMessage(response)+"\"", null);
		return;
	}

	public void run() {
		while (true) {
			if (getMessage()) {
				JsonObject cmd = readCommand();
				if (cmd == null) {
					try {
						client.close();
					} catch (Exception e) {
					}
					return;
				}
				executeCommand(cmd);
				m = null;
			}
		}

	}

}
