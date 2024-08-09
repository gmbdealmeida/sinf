package main;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

/**
 * This class represents a server.
 * 
 * @author Artur Cancela 51153 && Diogo Ramos 51220 & Guilherme Almeida 52052
 * @date Abril 2021
 */
public class MyDoctorServer {
	/**
	 * Initializes the server.
	 * 
	 * @param args: Not used
	 */
	public static void main(String[] args) throws Exception {
		MyDoctorServer server = new MyDoctorServer();
		server.startServer();
	}

	
	/**
	 * Starts the server.
	 * 
	 * Begins by asking the user the TCP port to connect to.
	 * Ends the program if the port isn't valid.
	 * 
	 * Creates a new socket with given TCP port and sets up a new file 
	 * to store user data if it hasn't been done already.
	 * 
	 * Then waits and processes client's requests by assigning them to
	 * a given thread (indefinitely).
	 */
	public void startServer() throws Exception {
		// Asks for TCP port.
		Scanner input = new Scanner(System.in);
		System.out.println("Escolha o porto TCP:");
		String chosenTcpPort = input.nextLine();
		
		// Checks if given TCP Port is valid.
		if(chosenTcpPort.equals("23456")) {
			System.setProperty("javax.net.ssl.keyStore", "keyStores/keystore.tls.server");
			System.setProperty("javax.net.ssl.keyStorePassword", "123456");
			
			ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();
			ServerSocket serverSocket = ssf.createServerSocket(23456);
			
			File passwords = new File("passwords.txt");
			boolean passwordsFileExists = !passwords.createNewFile();
			
			File mac = new File("passwords.mac");
			boolean macFileExists = !mac.createNewFile();
			
			// Checks if user's data file already exists.
			if(!passwordsFileExists && !macFileExists) {
				// Asks Main_admin for password.
				System.out.println("Bem-vindo Administrador_base!");
				System.out.println("\n" + "Escolha a sua nova password:");
				String mainAdminPassword = input.nextLine();
				
				// Creates password's file with Main_admin data.
				createPasswordsFile(passwords, mainAdminPassword);
				System.out.println("Ficheiro de passwords criado com sucesso.");
				
				// Creates Main_admin a new repository.
				createMainAdminRepository();
				
				// Asks Main_admin for MAC password.
				System.out.println("\n" + "Escolha uma nova password MAC:");
				String macPassword = input.nextLine();
				input.close();
				
				// Generates key to be used on obtaining the password's MAC.
				SecretKey hmacKey = new SecretKeySpec(macPassword.getBytes(), "HmacSHA256");
				
				// Obtains the password's MAC.
				byte[] passwordsMAC = generatePasswordsMAC(passwords, hmacKey);
				
				// Creates a file with the obtained password's MAC.
				createPasswordsMACFile(passwordsMAC);
				System.out.println("Ficheiro MAC criado com sucesso.");
				
				// HANDLE CLIENT REQUESTS
				handleClientRequests(serverSocket, hmacKey);
			}
			
			else if(passwordsFileExists && macFileExists){
				System.out.println("Bem-vindo de volta, Administrador_base!");
				
				System.out.println("\n" + "Introduza a password MAC:");
				String macPassword = input.nextLine();
				input.close();
				
				// Generates key to be used on obtaining the password's MAC.
				SecretKey hmacKey = new SecretKeySpec(macPassword.getBytes(), "HmacSHA256");
				
				// Obtains the current password's MAC.
				byte[] currentPasswordsMAC = generatePasswordsMAC(passwords, hmacKey);
				
				// Verifies if 	the current password's MAC matches with
				// the stored password's MAC.
				boolean isCorrectMAC = verifyMAC(mac, currentPasswordsMAC);
				
				if(isCorrectMAC) {
					System.out.println("Ficheiro MAC correto!");
					
					// HANDLE CLIENT REQUESTS
					handleClientRequests(serverSocket, hmacKey);
				}
				
				else {
					System.out.println("ERRO! O ficheiro MAC foi alterado.");
					System.out.println("Servidor terminado.");
				}
			}
			
			else if(passwordsFileExists && !macFileExists) {
				System.out.println("Bem-vindo de volta, Administrador_base!");
				
				System.out.println("\n" + "ERRO! O ficheiro MAC não existe.");
				System.out.println("Pretende continuar[S/n]?");
				String proceedAnswer = input.nextLine();
				boolean proceed = proceedAnswer.equals("S") || proceedAnswer.equals("Sim")
								  || proceedAnswer.equals("s") || proceedAnswer.equals("sim");
				
				if(proceed) {
					// Asks Main_admin for MAC password.
					System.out.println("\n" + "Escolha uma nova password MAC:");
					String macPassword = input.nextLine();
					input.close();
					
					// Generates key to be used on obtaining the password's MAC.
					SecretKey hmacKey = new SecretKeySpec(macPassword.getBytes(), "HmacSHA256");
					
					// Obtains the password's MAC.
					byte[] passwordsMAC = generatePasswordsMAC(passwords, hmacKey);
					
					// Creates a file with the obtained password's MAC.
					createPasswordsMACFile(passwordsMAC);
					System.out.println("Ficheiro MAC criado com sucesso.");
					
					// HANDLE CLIENT REQUESTS
					handleClientRequests(serverSocket, hmacKey);
				}
				
				else {
					input.close();
					mac = new File("passwords.mac");
					mac.delete();
					
					System.out.println("Servidor terminado.");
				}
				
			}
			
			else {
				input.close();
				passwords = new File("passwords.txt");
				passwords.delete();
				System.out.println("ERRO! O ficheiro de passwords não existe.");
				System.out.println("Servidor terminado.");
			}
		}
		
		else {
			input.close();
			System.out.println("ERRO! O porto TCP escolhido não é valido.");
		}
	}
	
	/**
	 * Creates password's file with Main_admin data.
	 * @param passwords: The file to be created.
	 * @param mainAdminPassword: The password given by Main_admin.
	 */
	public static void createPasswordsFile(File passwords, String mainAdminPassword) throws Exception {
		// Creates a secure password to store on user's data file.
		String[] mainAdminSecurePasswordAndSalt = hashPasswordWithSalt(mainAdminPassword);
		String mainAdminSecurePassword = mainAdminSecurePasswordAndSalt[0];
		String mainAdminSalt = mainAdminSecurePasswordAndSalt[1];
		
		// Writes Main_admin data to passwords file.
		FileOutputStream passwordsFile = new FileOutputStream(passwords, true);
		String userData = "1;Administrador_base;" 
						  + mainAdminSecurePassword + ";" + mainAdminSalt
						  + ";admin" + "\n";
		byte[] userDataInBytes = userData.getBytes();
		passwordsFile.write(userDataInBytes);
		passwordsFile.close();
	}
	
	
	/**
	 * Secures the given password by hashing it with a salt.
	 * @param password: The password to be secured.
	 */
	public static String[] hashPasswordWithSalt(String password) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		
		// Gets a random salt in order to secure the password.
		byte[] salt = getSalt();
				
		md.update(salt);
		
		byte[] hashWithSalt = md.digest(password.getBytes());
		
		// An array with the secure password and used salt.
		String[] securePasswordAndSalt = new String[]
										 {Base64.getEncoder().encodeToString(hashWithSalt), 
									      Base64.getEncoder().encodeToString(salt)};
		
		return securePasswordAndSalt;
	}
	
	
	/**
	 * Generates a random salt.
	 */
    public static byte[] getSalt() throws NoSuchAlgorithmException {
        SecureRandom random = new SecureRandom();
        
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        
        return salt;
    }
	
    
	/**
	 * Creates Main_admin repository.
	 */
	public static void createMainAdminRepository() {
		File newUserDirectory = new File("serverRepository/1");
		newUserDirectory.mkdir();
	}
	
	
	/**
	 * Generates MAC of password's file.
	 * @param passwordsFile: The password's file.
	 * @param hmacKey: The key to be used on generating the MAC.
	 */
    public static byte[] generatePasswordsMAC(File passwordsFile, SecretKey hmacKey) throws Exception {
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(hmacKey);
		
		FileInputStream inPasswords = new FileInputStream(passwordsFile);
		
		byte[] buffer = new byte[2048];
		
		int bytesRead = inPasswords.read(buffer);
		
		while(bytesRead != -1) {
			mac.update(buffer, 0, bytesRead);
			bytesRead = inPasswords.read(buffer);
		}
		
		inPasswords.close();
		
		return mac.doFinal();
    }
    
    
	/**
	 * Creates a file with the password's MAC.
	 * @param passwordsMAC: The MAC of the password's file.
	 */
    public static void createPasswordsMACFile(byte[] passwordsMAC) throws Exception {
		FileOutputStream outMAC = new FileOutputStream("passwords.mac");
		outMAC.write(passwordsMAC);
		
		outMAC.close();
    }
    
    
	/**
	 * Verifies if the current password's MAC matches with
	 * the stored password's MAC.
	 * @param mac: The file of the last stored password's MAC.
	 * @param currentPasswordsMAC: The current password's MAC.
	 */
    public static boolean verifyMAC(File mac, byte[] currentPasswordsMAC) throws Exception {
		FileInputStream inStoredPasswordsMAC = new FileInputStream(mac);
		
		byte[] storedPasswordsMAC = new byte[32];
			
		inStoredPasswordsMAC.read(storedPasswordsMAC, 0, 32);
		inStoredPasswordsMAC.close();
			
		boolean isCorrectMAC = Arrays.equals(currentPasswordsMAC, storedPasswordsMAC);
		
		return isCorrectMAC;
    }
    
    
	/**
	 * Handles the requests received by the clients.
	 * @param ServerSocket: The socket of running server.
	 * @param hmacKey: The key to be used on verifying the MAC
	 * 				   while the server is running.
	 */
	public static void handleClientRequests(ServerSocket serverSocket, SecretKey hmacKey) throws Exception {
		ServerThread clientThread;
		
		do {
			// Waits for client's request.
			Socket inSocket = serverSocket.accept();
			
			// Receives client's request and creates a new thread where
			// the request will be processed.
			clientThread = new ServerThread(inSocket, hmacKey);
			clientThread.start();
			clientThread.join();
			
			//serverSocket.close();
			
		} while(!clientThread.hadRuntimeError());
		
		System.out.println("Servidor terminado.");
	}
	
	
	/**
	 * This class represents a server thread.
	 */
	static class ServerThread extends Thread {
		private Socket socket;
		private SecretKey hmacKey;
		private volatile boolean runtimeError;
		
		/**
		 * Constructor, with given socket.
		 * @param socket: The assigned socket to process the client's request.
		 */
		ServerThread(Socket socket, SecretKey hmacKey) {
			this.socket = socket;
			this.hmacKey = hmacKey;
			this.runtimeError = false;
		}
		

		/**
		 * Processes the client's request.
		 * 
		 * Begins by receiving the client's desired commands.
		 * 
		 * Then sets out to process the client's request.
		 * 
		 * Starts by checking if passed user exists 
		 * and if the correct password was inserted.
		 * 
		 * Finally, takes action according to given client command.
		 * 
		 * An error message is given whenever an option or command isn't valid.
		 */
		public void run() {
			try {
				File passwords = new File("passwords.txt");
				File mac = new File("passwords.mac");
				
				ObjectOutputStream outStream = new ObjectOutputStream(this.socket.getOutputStream());
				ObjectInputStream inStream = new ObjectInputStream(this.socket.getInputStream());
				
				String unexpected = "ERRO! Ocorreu algo inesperado."
									+ "\n" + "Por favor contacte a administração para +info.";
				
				String[] inArgs = null;
				
				try {
					// Receives all necessary options and commands
					// from the client in order to process his request.
					inArgs = (String[]) inStream.readObject();
					
					// PROCESSING starts here.
					List<String> args = new ArrayList<String>(Arrays.asList(inArgs));
					
					// Set of some of the possible errors.
					String userDoesNotExist = "ERRO! Este utilizador não existe.";
					String incorrectPassword = "ERRO! Password incorreta.";
					String noPermission = "ERRO! Este utilizador não tem as permissões "
					        			   + "necessárias para executar este comando.";
					String noValidCommand = "ERRO! Não foi inserido qualquer comando válido.";
					
					// Obtains the current password's MAC.
					byte[] currentPasswordsMAC = generatePasswordsMAC(passwords, this.hmacKey);
					
					// Verifies if 	the current password's MAC matches with
					// the stored password's MAC.
					boolean isCorrectMAC = verifyMAC(mac, currentPasswordsMAC);
					
					if(isCorrectMAC) {
						// Checks if user (the client) actually exists.
						String maybeUserID = args.get(1);
						boolean userExists = checkIfUserExists(passwords, maybeUserID);
						
						if(!userExists) {
							sendErrorMessage(outStream, userDoesNotExist);
						}
						
						else {
							// Obtains the current password's MAC.
							currentPasswordsMAC = generatePasswordsMAC(passwords, this.hmacKey);
							
							// Verifies if 	the current password's MAC matches with
							// the stored password's MAC.
							isCorrectMAC = verifyMAC(mac, currentPasswordsMAC);
							
							if(isCorrectMAC) {
								// Assignment for readability purposes.
								String userID = maybeUserID;
								
								// Checks if given password matches user's correct password.
								String maybeUserPassword = args.get(5);
								String userPassword = getUserPassword(passwords, userID);
								String userSalt = getUserSalt(passwords, userID);
								
								// Verifies if given user password matches with actual user password.
								boolean isCorrectPassword = verifyPassword(maybeUserPassword, userPassword, userSalt);
								
								// Meanwhile, retrieves user's type...
								String userType = getUserType(passwords, userID);
								
								if(!isCorrectPassword) {
									sendErrorMessage(outStream, incorrectPassword);
								}
								
								// Checks if command is -mu (List Users).
								else if(args.contains("-mu")) {
									// Obtains the current password's MAC.
									currentPasswordsMAC = generatePasswordsMAC(passwords, this.hmacKey);
									
									// Verifies if 	the current password's MAC matches with
									// the stored password's MAC.
									isCorrectMAC = verifyMAC(mac, currentPasswordsMAC);
									
									if(isCorrectMAC) {
										// Checks if user has permissions to use this command.
										if(userType.equals("admin") || userType.equals("medico") || userType.equals("tecnico")) {
											listUsers(passwords, outStream);
										}

										else {
											sendErrorMessage(outStream, noPermission);
										}
									}
									
									else {
										sendErrorMessage(outStream, unexpected);
										
										this.setRuntimeError();
										
										System.out.println("\n" + "ERRO! O ficheiro MAC foi alterado.");
									}
								}
								
								// Checks if command is -md (List Own User's Documents).
								else if(args.contains("-md")) {
									// Checks if user has permissions to use this command.
									if(userType.equals("utente")) {
										listDocuments(args, outStream);
									}
									
									else {
										sendErrorMessage(outStream, noPermission);
									}
								}
								
								// Checks if command is -mx (List Some User's Documents).
								else if(args.contains("-mx")) {
									// Checks if user has permissions to use this command.
									if(userType.equals("medico")) {
										listDocuments(args, passwords, outStream);
									}
									
									else {
										sendErrorMessage(outStream, noPermission);
									}
								}
								
								// Checks if command is -d (Download Own User's Document).
								else if(args.contains("-d")) {
									// Checks if user has permissions to use this command.
									if(userType.equals("utente")) {
										downloadDocument(args, outStream);
									}
									
									else {
										sendErrorMessage(outStream, noPermission);
									}
								}
								
								// Checks if command is -du (Download Some User's Document).
								else if(args.contains("-du")) {
									// Obtains the current password's MAC.
									currentPasswordsMAC = generatePasswordsMAC(passwords, this.hmacKey);
									
									// Verifies if 	the current password's MAC matches with
									// the stored password's MAC.
									isCorrectMAC = verifyMAC(mac, currentPasswordsMAC);
									
									if(isCorrectMAC) {
										// Checks if user has permissions to use this command.
										if(userType.equals("medico")) {
											downloadDocument(args, passwords, outStream);
										}
										
										else {
											sendErrorMessage(outStream, noPermission);
										}
									}
									
									else {
										sendErrorMessage(outStream, unexpected);
										
										this.setRuntimeError();
										
										System.out.println("\n" + "ERRO! O ficheiro MAC foi alterado.");
									}
								}
								
								// Checks if command is -su (Upload document from Client).
								else if(args.contains("-su")) {
									// Obtains the current password's MAC.
									currentPasswordsMAC = generatePasswordsMAC(passwords, this.hmacKey);
									
									// Verifies if 	the current password's MAC matches with
									// the stored password's MAC.
									isCorrectMAC = verifyMAC(mac, currentPasswordsMAC);
									
									if(isCorrectMAC) {
										// Checks if user has permissions to use this command.
										if(userType.equals("medico") || userType.equals("tecnico")) {
											uploadDocument(args, passwords, outStream, inStream);
										}
										
										else {
											sendErrorMessage(outStream, noPermission);
										}
									}
									
									else {
										sendErrorMessage(outStream, unexpected);
										
										this.setRuntimeError();
										
										System.out.println("\n" + "ERRO! O ficheiro MAC foi alterado.");
									}
								}
								
								// Checks if command is -c (Create New User).
								else if(args.contains("-c")) {
									// Obtains the current password's MAC.
									currentPasswordsMAC = generatePasswordsMAC(passwords, this.hmacKey);
									
									// Verifies if 	the current password's MAC matches with
									// the stored password's MAC.
									isCorrectMAC = verifyMAC(mac, currentPasswordsMAC);
									
									if(isCorrectMAC) {
										// Checks if user has permissions to use this command.
										if(userType.equals("admin")) {
											createNewUser(args, passwords, this.hmacKey, outStream);
										}
										
										else {
											sendErrorMessage(outStream, noPermission);
										}
									}
									
									else {
										sendErrorMessage(outStream, unexpected);
										
										this.setRuntimeError();
										
										System.out.println("\n" + "ERRO! O ficheiro MAC foi alterado.");
									}
								}
								
								else {
									sendErrorMessage(outStream, noValidCommand);
								}
							}
							
							else {
								sendErrorMessage(outStream, unexpected);
								
								this.setRuntimeError();
								
								System.out.println("\n" + "ERRO! O ficheiro MAC foi alterado.");
							}
						}
					}
					
					else {
						sendErrorMessage(outStream, unexpected);
						
						this.setRuntimeError();
						
						System.out.println("\n" + "ERRO! O ficheiro MAC foi alterado.");
					}

				} catch (ClassNotFoundException e) {
					e.printStackTrace();
					
				} catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
					
				} catch (Exception e) {
					e.printStackTrace();
				}
				
				outStream.close();
				inStream.close();
				
				this.socket.close();

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		
		/**
		 * Checks if server had runtime error.
		 */
		public boolean hadRuntimeError() {
			return this.runtimeError;
		}
	
		
		/**
		 * Server had runtime error.
		 */
		void setRuntimeError() {
			this.runtimeError = true;
		}
		
		
		/**
		 * Checks if given user exists the file where the user's data is stored.
		 * @param file: The file where the user's data is stored.
		 * @param userID: The ID of the user to check.
		 * @returns true if user is in given file. 
		 * 			false otherwise.
		 */
		static boolean checkIfUserExists(File file, String userID) throws FileNotFoundException {
			boolean result = false;
			
			Scanner scanner = new Scanner(new FileInputStream(file));
			
			// Goes through file while the user isn't found.
			while(scanner.hasNextLine()) {
				String line = scanner.nextLine();
				List<String> splitLine = new ArrayList<String>(Arrays.asList(line.split(";")));
				
				if(splitLine.get(0).equals(userID)) {
					// USER FOUND.
					result = true;
					
					return result;
				}
			}
			
			// User NOT Found.
			return result;
		}
		
		
		/**
		 * Retrieve the user's name from the file where the user's data is stored.
		 * @param file: The file where the user's data is stored.
		 * @param userID: The ID of the user to retrieve the name from.
		 * @requires checkIfUserExists(userID)
		 */
		static String getUserName(File file, String userID) throws FileNotFoundException {
			String userName = "";
			
			Scanner scanner = new Scanner(new FileInputStream(file));
			
			// Goes through file while the user's name isn't found.
			while(scanner.hasNextLine()) {
				String line = scanner.nextLine();
				List<String> splitLine = new ArrayList<String>(Arrays.asList(line.split(";")));
				
				if(splitLine.get(0).contentEquals(userID)) {
					// USER'S NAME FOUND.
					userName = splitLine.get(1);
					
					return userName;
				}
			}
			
			// User's name NOT found.
			return userName;
		}
		
		
		/**
		 * Retrieve the user's password from the file where the user's data is stored.
		 * @param file: The file where the user's data is stored.
		 * @param userID: The ID of the user to retrieve the password from.
		 * @requires checkIfUserExists(userID)
		 */
		static String getUserPassword(File file, String userID) throws FileNotFoundException {
			String userPassword = "";
			
			Scanner scanner = new Scanner(new FileInputStream(file));
			
			// Goes through file while the user's password isn't found.
			while(scanner.hasNextLine()) {
				String line = scanner.nextLine();
				List<String> splitLine = new ArrayList<String>(Arrays.asList(line.split(";")));
				
				if(splitLine.get(0).equals(userID)) {
					// USER'S PASSWORD FOUND.
					userPassword = splitLine.get(2);
					
					return userPassword;
				}
			}
			
			// User's password NOT found.
			return userPassword;
		}
		
		
		/**
		 * Retrieve the user's associated salt from the file where the user's data is stored.
		 * @param file: The file where the user's data is stored.
		 * @param userID: The ID of the user to retrieve the associated salt from.
		 * @requires checkIfUserExists(userID)
		 */
		static String getUserSalt(File file, String userID) throws FileNotFoundException {
			String userSalt = "";
			
			Scanner scanner = new Scanner(new FileInputStream(file));
			
			// Goes through file while the user's type isn't found.
			while(scanner.hasNextLine()) {
				String line = scanner.nextLine();
				List<String> splitLine = new ArrayList<String>(Arrays.asList(line.split(";")));
				
				if(splitLine.get(0).equals(userID)) {
					// USER'S SALT FOUND.
					userSalt = splitLine.get(3);
					
					return userSalt;
				}
			}
			
			// User's salt NOT found.
			return userSalt;
		}
		
		
		/**
		 * Retrieve the user's type from the file where the user's data is stored.
		 * @param file: The file where the user's data is stored.
		 * @param userID: The ID of the user to retrieve the type from.
		 * @requires checkIfUserExists(userID)
		 */	
		static String getUserType(File file, String userID) throws FileNotFoundException {
			String userType = "";
			
			Scanner scanner = new Scanner(new FileInputStream(file));
			
			// Goes through file while the user's type isn't found.
			while(scanner.hasNextLine()) {
				String line = scanner.nextLine();
				List<String> splitLine = new ArrayList<String>(Arrays.asList(line.split(";")));
				
				if(splitLine.get(0).equals(userID)) {
					// USER'S TYPE FOUND.
					userType = splitLine.get(4);
					
					return userType;
				}
			}
			
			// User's type NOT found.
			return userType;
		}
		
		
		/**
		 * Lists all user's stored in user's data file.
		 * @param file: The file where the user's data is stored.
		 * @param outStream: The output stream used for sending information to the client.
		 */
		static void listUsers(File file, ObjectOutputStream outStream) throws IOException {
			StringBuilder sb = new StringBuilder();
			
			Scanner scanner = new Scanner(new FileInputStream(file));
			
			// Goes through the whole file.
			while(scanner.hasNextLine()) {
				// Retrieves necessary info from each line.
				String line = scanner.nextLine();
				List<String> splitLine = new ArrayList<String>(Arrays.asList(line.split(";")));
				sb.append(splitLine.get(0) + " " + splitLine.get(1) + " "
						  + splitLine.get(4) + "\n");
			}
			
			String answer = sb.toString();
			outStream.writeObject(answer);
		}
		
		
		/**
		 * Lists the documents of given user if there are documents to list.
		 * Otherwise sends appropriate error message to the client. 
		 * @param args: The arguments to get the client's options and commands from.
		 * @param outStream: The output stream used for sending information to the client.
		 * @requires args.get(i)!java.lang.ArrayIndexOutOfBoundException
		 */
		static void listDocuments(List<String> args, ObjectOutputStream outStream) throws IOException {
			// Gets ID of user to be listed (own user).
			String userID = args.get(1);
			File file = new File("serverRepository/" + userID);
			
			List<String> documents = Arrays.asList(file.list());
			
			// Checks if there are actually documents to list.
			if(!documents.isEmpty()) {
				StringBuilder sb = new StringBuilder();
				
				for(String document : documents) {
					sb.append(document + "\n");
				}
				
				String answer = sb.toString();
				outStream.writeObject(answer);
			}
			
			else {
				String answer = "ERRO! Você não tem documentos para listar.";
				outStream.writeObject(answer);
			}
		}
		
		
		/**
		 * Lists the documents of given user if he exists in user's data file.
		 * Otherwise sends appropriate error message to the client.
		 * Also sends appropriate error message to the client if there 
		 * are no documents to list.
		 * @param args: The arguments to get the client's options and commands from.
		 * @param file: The file where the user's data is stored.
		 * @param outStream: The output stream used for sending information to the client.
		 * @requires args.get(i)!java.lang.ArrayIndexOutOfBoundException
		 */
		static void listDocuments(List<String> args, File file, ObjectOutputStream outStream) throws IOException {
			// Gets ID of user to be listed (target user).
			String userToList = args.get(7);
			// Checks if target user actually exists.
			boolean userExists = checkIfUserExists(file, userToList);
			
			if(userExists) {
				File directory = new File("serverRepository/" + userToList);
				
				List<String> documents = Arrays.asList(directory.list());
				
				// Checks if there are actually documents to list.
				if(!documents.isEmpty()) {
					StringBuilder sb = new StringBuilder();
					
					for(String document : documents) {
						sb.append(document + "\n");
					}
					
					String answer = sb.toString();
					outStream.writeObject(answer);
				}
				
				else {
					String answer = "ERRO! O utilizador não tem documentos para listar.";
					outStream.writeObject(answer);
				}	
			}
			
			else {
				String answer = "ERRO! O utilizador a listar não existe.";
				outStream.writeObject(answer);
			}
		}
		
		
		/**
		 * Sends the necessary information to the client in order for him to 
		 * download desired document, if the document exists in the server's repository.
		 * Otherwise sends appropriate error message to the client.
		 * @param args: The arguments to get the client's options and commands from.
		 * @param outStream: The output stream used for sending information to the client.
		 * @requires args.get(i)!java.lang.ArrayIndexOutOfBoundException
		 */
		static void downloadDocument(List<String> args, ObjectOutputStream outStream) throws Exception {
			// Gets ID of user to download document from (own user).
			String userID = args.get(1);
			// Gets the document to be download name.
			String documentName = args.get(7);
			
			File document = new File("serverRepository/" + userID + "/" + documentName);
			
			// Checks if document to be downloaded actually exists.
			if(document.exists()) {
				Long documentSize = (Long) document.length();
				outStream.writeObject(documentSize);
				
				outStream.writeObject(documentName);
				
				outStream.writeObject(userID);
				
				// Retrieves ciphered AES key used on encrypting the document to be sent to the client.
				byte[] cipheredAESKey = getCipheredAESKey(documentName, userID);
				
				// The server's private key.
				Key privateKey = getPrivateKey();
				
				// Decipher the AES key.
				Key aesKey = decipherAESKey(cipheredAESKey, privateKey);
				
				// The cipher to be used on decrypting the document.
				Cipher cipher = getDecipher(aesKey, documentName, userID);
				
				
				FileInputStream inDocument = new FileInputStream(document);
				
				BufferedInputStream inDocumentBuff = new BufferedInputStream(inDocument);
				
				CipherInputStream inCipher = new CipherInputStream(inDocumentBuff, cipher);
				
				byte[] buffer = new byte[2048];
				int bytesRead;
				
				// Decrypts the document and sends it to the client.
				while( (bytesRead = inCipher.read(buffer, 0, 2048)) > 0) {
					outStream.write(buffer, 0, bytesRead);
				}
				
				inCipher.close();
				inDocumentBuff.close();
				inDocument.close();
				
				// Sends document's signature to the client.
				sendSignature(outStream, documentName, userID);
			}
			
			else {
				String answer = "ERRO! Este documento não existe.";
				outStream.writeObject(answer);
			}
		}
		
		
		/**
		 * Sends the necessary information to the client in order for him to 
		 * download desired document, if the document exists in the server's repository.
		 * Otherwise sends appropriate error message to the client.
		 * Also sends appropriate error message to the client if the user 
		 * to download from doesn't exist.
		 * @param args: The arguments to get the client's options and commands from.
		 * @param file: The file where the user's data is stored.
		 * @param outStream: The output stream used for sending information to the client.
		 * @requires args.get(i)!java.lang.ArrayIndexOutOfBoundException
		 */
		static void downloadDocument(List<String> args, File file, ObjectOutputStream outStream) throws Exception {
			// Gets ID of user to download document from (own user).
			String userID = args.get(1);
			// Gets ID of user to download document from (target user).
			String userToDownloadFrom = args.get(8);
			// Checks if target user actually exists.
			boolean userExists = checkIfUserExists(file, userToDownloadFrom);
			
			if(userExists) {
				// Gets the document to be download name.
				String documentName = args.get(7);
				
				File document = new File("serverRepository/" + userToDownloadFrom + "/" + documentName);
				
				// Checks if document to be sent actually exists.
				if(document.exists()) {
					
					Long documentSize = (Long) document.length();
					outStream.writeObject(documentSize);
					
					outStream.writeObject(documentName);
					
					outStream.writeObject(userID);
					
					// Retrieves ciphered AES key used on encrypting the document to be sent to the client.
					byte[] cipheredAESKey = getCipheredAESKey(documentName, userToDownloadFrom);
					
					// The server's private key.
					Key privateKey = getPrivateKey();
					
					// Decipher the AES key.
					Key aesKey = decipherAESKey(cipheredAESKey, privateKey);
					
					// The cipher to be used on decrypting the document.
					Cipher cipher = getDecipher(aesKey, documentName, userToDownloadFrom);
					
					
					FileInputStream inDocument = new FileInputStream(document);
					
					BufferedInputStream inDocumentBuff = new BufferedInputStream(inDocument);
					
					CipherInputStream inCipher = new CipherInputStream(inDocumentBuff, cipher);
					
					byte[] buffer = new byte[2048];
					int bytesRead;
					
					// Decrypts the document and sends it to the client.
					while( (bytesRead = inCipher.read(buffer, 0, 2048)) > 0) {
						outStream.write(buffer, 0, bytesRead);
					}
					
					inCipher.close();
					inDocumentBuff.close();
					inDocument.close();
					
					// Sends document's signature to the client.
					sendSignature(outStream, documentName, userToDownloadFrom);
				}
				
				else {
					String answer = "ERRO! Este documento não existe.";
					outStream.writeObject(answer);
				}	
			}
			
			else {
				String answer = "ERRO! O utilizador a partir do qual quer descarregar não existe.";
				outStream.writeObject(answer);
			}
		}
		
		
		/**
		 * Receives the necessary information from the client in order to 
		 * upload desired document to the server, uploading it if
		 * the user to upload to exists.
		 * Otherwise sends appropriate error message to the client.
		 * @param args: The arguments to get the client's options and commands from.
		 * @param file: The file where the user's data is stored.
		 * @param outStream: The output stream used for sending information to the client.
		 * @param inStream: The input stream used for receiving information from the client. 
		 * @requires args.get(i)!java.lang.ArrayIndexOutOfBoundException
		 */
		static void uploadDocument(List<String> args, File file, ObjectOutputStream outStream, ObjectInputStream inStream) throws Exception {
			// Gets ID of user to upload document to (target user).
			String userToUploadTo = args.get(8);
			// Checks if target user actually exists.
			boolean userExists = checkIfUserExists(file, userToUploadTo);
			
			if(userExists) {
				// Gets the document to be uploaded name.
				String documentName = args.get(7);
				// Gets the name of the user to upload document to.
				String userToUploadToName = getUserName(file, userToUploadTo);
				// Gets ID of user who sent the document to be uploaded.
				String userID = args.get(1);

				outStream.writeObject((Boolean) true);
				outStream.writeObject(documentName);
				outStream.writeObject(userToUploadToName);
				outStream.writeObject(userToUploadTo);
				outStream.writeObject(userID);
				
				Boolean documentExists = (Boolean) inStream.readObject();
				
				// Checks if document to be uploaded actually exists.
				if(documentExists) {
					Long documentSize = (Long) inStream.readObject();
					
					File document = new File("serverRepository/" + userToUploadTo + "/" + documentName);
					
					// Checks if document name is already being used.
					// If so renames it by adding _i. 
					if(document.exists()) {
						List<String> splitDocumentName = new ArrayList<String>(Arrays.asList(documentName.split("\\.")));
						int numFile = 1;
						File provDocument = new File("serverRepository/" + userToUploadTo + "/" + splitDocumentName.get(0) 
													 + "_" + numFile + "." + splitDocumentName.get(1));
						
						while(provDocument.exists()) {
							numFile++;
							provDocument = new File("serverRepository/" + userToUploadTo + "/" + splitDocumentName.get(0) 
													+ "_" + numFile + "." + splitDocumentName.get(1));
						}
						
						// Renaming will be done here.
						documentName = provDocument.getName();
					}
					
				    // Generates a random key to be used with the AES algorithm.
				    SecretKey aesKey = generateAESKey();
				    
				    // The cipher to be used on encrypting the document.
				    Cipher cipher = getCipher(aesKey, documentName, userToUploadTo);
				    
				    
					FileOutputStream outDocument = new FileOutputStream("serverRepository/" + userToUploadTo + "/" + documentName);
					
					BufferedOutputStream outDocumentBuff = new BufferedOutputStream(outDocument);
					
					CipherOutputStream outCipher = new CipherOutputStream(outDocumentBuff, cipher);
					
					byte[] buffer = new byte[2048];
					int bytesRead;
					
					// Retrieves document from client and creates new one 
					// on the server's repository that will be encrypted.
					while(documentSize > 0) {
						bytesRead = inStream.read(buffer, 0, (int) (documentSize < 2048 ? documentSize : 2048));
						outCipher.write(buffer, 0, bytesRead);
						documentSize = documentSize - bytesRead;
					}
					
					outCipher.close();
					outDocumentBuff.close();
					outDocument.close();
					
				    // The certificate corresponds to the server's public key.
					Certificate publicKey = getPublicKey();
					
					// Ciphers the AES key with the server's public key.
					cipherAESKey(aesKey, publicKey, documentName, userToUploadTo);
					
					// Receives document's signature from the client.
					receiveSignature(inStream, documentName, userToUploadTo, userID);
				}
			}
			
			else {
				String answer = "ERRO! O utilizador para o qual quer fazer upload não existe.";
				outStream.writeObject(answer);
			}
		}
		
		
		/**
		 * Creates new user in the file where the user's date is stored if 
		 * the user doesn't already exist.
		 * Otherwise sends appropriate error message to the client.
		 * Also sends appropriate error message to the client if
		 * the new user type isn't valid.
		 * @param args: The arguments to get the client's options and commands from.
		 * @param file: The file where the user's data is stored.
		 * @param outStream: The output stream used for sending information to the client.
		 * @requires args.get(i)!java.lang.ArrayIndexOutOfBoundException
		 */
		static void createNewUser(List<String> args, File file, SecretKey hmacKey, ObjectOutputStream outStream) throws Exception {
			// Gets user's to be created ID.
			String newUserID = args.get(7);
			// Checks if user's to be created ID is already being used.
			boolean userIDExists = checkIfUserExists(file, newUserID);
			
			if(!userIDExists) {
				// Gets user's to be created type.
				String newUserType = args.get(10);
				
				// Checks if the new user's type is valid.
				if(newUserType.equals("admin") || newUserType.equals("utente")
				   || newUserType.equals("medico") || newUserType.equals("tecnico")) {
					// Gets user's to be created name.
					String newUserName = args.get(8);
					// Gets user's to be created password.
					String newUserPassword = args.get(9);
					
					// Creates a secure password to store on user's data file.
					String[] newUserSecurePasswordAndSalt = hashPasswordWithSalt(newUserPassword);
					String newUserSecurePassword = newUserSecurePasswordAndSalt[0];
					String newUserSalt = newUserSecurePasswordAndSalt[1];
					
					// Writes the new user's data to the file where user's data is stored.
					FileOutputStream passwordsFile = new FileOutputStream(file, true);
					String userData = newUserID + ";" + newUserName + ";"
									  + newUserSecurePassword + ";" + newUserSalt + ";"
									  + newUserType + "\n";
					
					byte[] userDataInBytes = userData.getBytes();
					passwordsFile.write(userDataInBytes);
					passwordsFile.close();
					
					// Creates a repository for the new user.
					File newUserDirectory = new File("serverRepository/" + newUserID);
					newUserDirectory.mkdir();
					
					// Updates the password's MAC.
					byte[] passwordsMAC = generatePasswordsMAC(file, hmacKey);
					
					// Overwrites the old password's MAC file with
					// the newly updated one.
					createPasswordsMACFile(passwordsMAC);
					
					String answer = "O utilizador " + newUserName + " com o ID" + newUserID
							        + " vai ser criado.";
					outStream.writeObject(answer);
				}
				
				else {
					String answer = "ERRO! Tipo de utilizador inválido.";
					outStream.writeObject(answer);
				}
			}
			
			else {
				String answer = "ERRO! Este ID já está a ser utilizado.";
				outStream.writeObject(answer);
			}
		}
		
		
		/**
		 * Sends given error message to the client.
		 * @param outStream: The output stream used for sending information to the client.
		 * @param message: The error message to send to the client.
		 */
		static void sendErrorMessage(ObjectOutputStream outStream, String message) throws IOException {
			outStream.writeObject(message);
		}
		
		
		/**
		 * Secures the given password by hashing it with a salt.
		 * @param password: The password to be secured.
		 */
		static String[] hashPasswordWithSalt(String password) throws NoSuchAlgorithmException {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			
			// Gets a random salt in order to secure the password.
			byte[] salt = getSalt();
					
			md.update(salt);
			
			byte[] hashWithSalt = md.digest(password.getBytes());
			
			// An array with the secure password and used salt.
			String[] securePasswordAndSalt = new String[]
											 {Base64.getEncoder().encodeToString(hashWithSalt), 
										      Base64.getEncoder().encodeToString(salt)};
			
			return securePasswordAndSalt;
		}
		
		
		/**
		 * Generates a random salt.
		 */
	    static byte[] getSalt() throws NoSuchAlgorithmException {
	        SecureRandom random = new SecureRandom();
	        
	        byte[] salt = new byte[16];
	        random.nextBytes(salt);
	        
	        return salt;
	    }
	   
	    
		/**
		 * Verifies if given user password matches with actual user password.
		 * @param maybeUserPassword: The given user password.
		 * @param userPassword: The actual user password.
		 * @param userSalt: The salt used on securing the actual user password.
		 */
	    static boolean verifyPassword(String maybeUserPassword, String userPassword, String userSalt) throws NoSuchAlgorithmException {
	    	MessageDigest md = MessageDigest.getInstance("SHA-256");
	    	byte[] salt = Base64.getDecoder().decode(userSalt);
	    	
	    	md.update(salt);
	    	
	    	byte[] hashWithSalt = md.digest(maybeUserPassword.getBytes());
	    	
	    	boolean isCorrectPassword = Base64.getEncoder().encodeToString(hashWithSalt).equals(userPassword);
	    	
	    	return isCorrectPassword;
	    }
	    
	    
		/**
		 * Receives the digital signature associated with uploaded document.
		 * @param inStream: The input stream used for receiving information from the client.
		 * @param documentName: The name of the uploaded document.
		 * @param userToUploadTo: The ID of the user to whom the document was uploaded.
		 * @param userID: The ID of the user who sent the document.
		 */
	    static void receiveSignature(ObjectInputStream inStream, String documentName, String userToUploadTo, String userID) throws Exception {
			byte[] signature = (byte[]) inStream.readObject();
			
			FileOutputStream outSignature = new FileOutputStream("serverRepository/" + userToUploadTo + "/" 
																 + documentName + ".signed." + userID);
			outSignature.write(signature);
			
			outSignature.close();
	    }
	    
	    
		/**
		 * Sends the digital signature associated with the document asked by the client.
		 * @param outStream: The output stream used for sending information to the client.
		 * @param documentName: The name of the sent document asked by the client.
		 * @param userID: The ID of the user who requested the download.
		 */
	    static void sendSignature(ObjectOutputStream outStream, String documentName, String userID) throws Exception {
			File userRepository = new File("serverRepository/" + userID);
			File[] userRepositoryFiles = userRepository.listFiles();
			
			for(File file : userRepositoryFiles) {
				if(file.getName().contains(documentName + ".signed")) {
					FileInputStream inUploaderSignature = new FileInputStream("serverRepository/" + userID 
																	  + "/" + file.getName());
					
					byte[] buffer = new byte[256];
					
					inUploaderSignature.read(buffer, 0, 256);
					
					outStream.write(buffer);
					outStream.writeObject(file.getName());
					
					inUploaderSignature.close();
				}
			}
	    }

	    
		/**
		 * Generates a random 128 bits AES Key.
		 */
	    static SecretKey generateAESKey() throws Exception {
		    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		    keyGenerator.init(128);
		    SecretKey aesKey = keyGenerator.generateKey();
		    
		    return aesKey;
	    }
	    
	    
		/**
		 * Creates the cipher to be used on the process of encrypting the document.
		 * @param aesKey: The AES key to be used on the process of encrypting the document.
		 * @param documentName: The name of the document to be encrypted.
		 * @param userToUploadTo: The ID of the user to whom the encrypted document is going to be uploaded.
		 */
	    static Cipher getCipher(SecretKey aesKey, String documentName, String userToUploadTo) throws Exception {
	    	Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
	    	
		    byte[] iv = new byte[cipher.getBlockSize()];
		    SecureRandom.getInstance("SHA1PRNG").nextBytes(iv);
		    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
		    
		    FileOutputStream outIV = new FileOutputStream("serverRepository/" + userToUploadTo + "/" + documentName + ".iv");
		    outIV.write(iv);
		    outIV.close();
		    
		    cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivParameterSpec);
		    
		    return cipher;
	    }
	    
	    
		/**
		 * Creates the decipher to be used on the process of decrypting the document.
		 * @param aesKey: The AES key to be used on the process of decrypting the document.
		 * @param documentName: The name of the document to be decrypted.
		 * @param userID: The ID of the user to whom the decrypted document belongs.
		 */
	    static Cipher getDecipher(Key aesKey, String documentName, String userID) throws Exception {
			FileInputStream inIV = new FileInputStream("serverRepository/" + userID + "/" + documentName + ".iv");
			IvParameterSpec ivParameterSpec = new IvParameterSpec(inIV.readAllBytes());
			inIV.close();
			
			Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, aesKey, ivParameterSpec);
			
			return cipher;
	    }
	    
	    
		/**
		 * Retrieves the server's public key from its keystore.
		 */
	    static Certificate getPublicKey() throws Exception {
	    	FileInputStream keyStoreFile = new FileInputStream("keyStores/keystore.server");
		    KeyStore keyStore = KeyStore.getInstance("PKCS12");
		    keyStore.load(keyStoreFile, "meme1234".toCharArray());
		    Certificate publicKey = keyStore.getCertificate("server");
		    
		    return publicKey;
	    }
	    
	    
		/**
		 * Retrieves the server's private key from its keystore.
		 */
	    static Key getPrivateKey() throws Exception {
			FileInputStream keyStoreFile = new FileInputStream("keyStores/keystore.server");
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(keyStoreFile, "meme1234".toCharArray());
			Key privateKey = keyStore.getKey("server", "meme1234".toCharArray());
			
			return privateKey;
	    }
	    
	    
		/**
		 * Ciphers the AES key used on the process of encrypting the document.
		 * @param aesKey: The AES key used on the process of encrypting the document.
		 * @param publicKey: The public key to cipher the AES key.
		 * @param documentName: The name of the encrypted document.
		 * @param userToUploadTo: The ID of the user to whom the encrypted document was uploaded.
		 */
	    static void cipherAESKey(SecretKey aesKey, Certificate publicKey, String documentName, String userToUploadTo) throws Exception {
		    Cipher cipher = Cipher.getInstance("RSA");
		    cipher.init(Cipher.WRAP_MODE, publicKey);
		    
		    byte[] keyEncoded = cipher.wrap(aesKey);
		    
		    FileOutputStream outAESKey = new FileOutputStream("serverRepository/" + userToUploadTo + 
		    											"/" + documentName + ".key");
		    outAESKey.write(keyEncoded);
		    outAESKey.close();
	    }
	    
	    
		/**
		 * Deciphers the AES key to be used on the process of decrypting the document.
		 * @param cipheredAESKey: The AES key to be deciphered.
		 * @param privateKey: The private key to decipher the AES key.
		 */
	    static Key decipherAESKey(byte[] cipheredAESKey, Key privateKey) throws Exception {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.UNWRAP_MODE, privateKey);
			Key aesKey = cipher.unwrap(cipheredAESKey, "AES", Cipher.SECRET_KEY);
			
			return aesKey;
	    }
	    
	    
		/**
		 * Retrieves the AES key used on the process of encrypting the document.
		 * @param documentName: The name of the encrypted document.
		 * @param userID: The ID of the user to whom the encrypted document belongs.
		 */
	    static byte[] getCipheredAESKey(String documentName, String userID) throws Exception {
			FileInputStream inAESKey = new FileInputStream("serverRepository/" + userID + "/" + documentName + ".key");
			
			// The 256 bytes correspond to the 2048 bits of an RSA key.
			byte[] cipheredAESKey = new byte[256];
			inAESKey.read(cipheredAESKey);
			inAESKey.close();
			
			return cipheredAESKey;
	    }
	}
}
