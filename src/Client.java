import java.net.Socket;
import java.util.Scanner;

public class Client {

	public static void main(String[] args) {
		if (args.length < 1) {
			System.err.print("Usage: port\n");
			System.exit(1);
		}

		int port = Integer.parseInt(args[0]);
	
		try {
			Scanner sc = new Scanner(System.in);
			Socket s = new Socket("localhost", port);
			ClientActions c = new ClientActions(s);
			System.out.println("Started client on port " + port + "\n");
			
			String alg = "";
			while (true) {
				System.out.print("Please choose your cipher algorithm for this session (RSA/DES/AES):\n> ");
				alg = sc.nextLine().toUpperCase();
				if (alg.equals("RSA") || alg.equals("DES") || alg.equals("AES")) break;
				System.out.println();
			}
			
			c.login(alg);
			String op = "";
			
			while (true) {
				System.out.println();
				System.out.println("-------------------------");
				System.out.println("|  Message Server Menu  |");
				System.out.println("|                       |");
				System.out.println("| 1 - List users        |");
				System.out.println("| 2 - New messages      |");
				System.out.println("| 3 - All/sent messages |");
				System.out.println("| 4 - Send message      |");
				System.out.println("| 5 - Read message      |");
				System.out.println("| 6 - Message status    |");
				System.out.println("| 7 - Exit              |");
				System.out.println("-------------------------");
				System.out.print("\nPlease pick an option:\n> ");
				op = sc.nextLine();
				
				if (op.equals("1")) {
					System.out.print("Type an ID (\"0\" or \"all\" will display everyone).\n> ");
					String i = sc.nextLine();
					if (i.equals("all")) i = "0";
					try {
						c.list(Integer.parseInt(i));
					} catch (NumberFormatException e) {
						System.out.println("ID must be a number or \"all\".");
					}
					
				} else if (op.equals("2")) {
					c.mnew(c.getID());
					
				} else if (op.equals("3")) {
					c.all(c.getID());
				
				} else if (op.equals("4")) {
					System.out.print("ID of the receiver?\n> ");
					String i = sc.nextLine();
					System.out.print("Please type your message below.\n> ");
					String m = sc.nextLine();
					try {
						c.send(c.getID(), Integer.parseInt(i), m);
					} catch (NumberFormatException e) {
						System.out.println("ID must be a number.");
					}
					
				} else if (op.equals("5")) {
					System.out.print("Name of the message?\n> ");
					String m = sc.nextLine();
					c.recv(c.getID(), m);
					
				} else if (op.equals("6")) {
					System.out.print("Name of the message?\n> ");
					String m = sc.nextLine();
					c.status(c.getID(), m);
					
				} else if (op.equals("7")) {
					System.out.println("Shutting down.");
					sc.close();
					s.close();
					System.exit(0);
					
				} else {
					System.out.println("Option not found.");
				}
			}

		} catch (Exception e) {
			System.err.print("Cannot open socket: " + e);
			System.exit(1);
		}
	
	}
	
}