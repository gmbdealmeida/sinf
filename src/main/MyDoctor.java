package main;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

/**
 * Esta classe representa um cliente.
 * 
 * @author Artur Cancela 51153 && Diogo Ramos 51220 & Guilherme Almeida 52052
 * @date Abril 2021
 */
public class MyDoctor {
	/**
	 * Receives and handles the client's request.
	 * 
	 * Begins by checking if client inserted all necessary options and commands.
	 * Ends the program otherwise.
	 * 
	 * Assigns client's socket with desired IP address and TCP port.
	 * 
	 * Follows up by checking if password was given, asking it otherwise.
	 * 
	 * Then sends the server all necessary information in order for him to be
	 * able to process the request, waiting for server's response, finalising
	 * the process when it is given.
	 * 
	 * @param args: The client's options and commands.
	 */
	public static void main(String[] args) throws Exception {
		System.out.println("Olá CLIENTE!" + "\n");
		
		// Checks if mandatory options are being inserted.
		if(args[0].equals("-u") && args[2].equals("-a") && args[3].equals("127.0.0.1:23456")) {
			System.setProperty("javax.net.ssl.trustStore", "keyStores/truststore.tls.client");
			System.setProperty("javax.net.ssl.trustStorePassword", "123456");
			
			SocketFactory sf = SSLSocketFactory.getDefault();
			Socket socket = sf.createSocket("127.0.0.1", 23456);
			  
			ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
			ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
			
			// Checks if password was inserted.
			if(!args[4].equals("-p")) {
				String password = askPassword();
				args = getNewArgs(args, password);
			}
				
			outStream.writeObject(args);
				
			// Waits for answer.
			Object answer = inStream.readObject();
			
			// Checks for -d option and -du option.
			if(answer.getClass() == Long.class) {
				Long documentSize = (Long) answer;
				downloadDocument(inStream, documentSize);
			}
			
			// Checks for -su option.
			else if(answer.getClass() == Boolean.class) {
				uploadDocument(outStream, inStream);
			}
			
			// All other answers.
			else {
				String result = (String) answer;
				System.out.println(result);	
			}
			
			outStream.close();
			inStream.close();
			socket.close();
		}
		
		else if(!args[0].equals("-u")) {
			System.out.println("ERRO! Opção -u não inserida.");
		}
		
		else if(!args[2].equals("-a")) {
			System.out.println("ERRO! Opção -a não inserida.");
		}
		
		else if(!args[3].equals("127.0.0.1:23456")){
			System.out.println("ERRO! O endereço IP ou porto TCP inseridos são inválidos.");
		}
	}
	
	
	/**
	 * Asks the client for his password.
	 */
	public static String askPassword() {
		Scanner input = new Scanner(System.in);
		System.out.println("Insira a sua password:");
		String password = input.nextLine();
		input.close();
		
		return password;
	}
	
	/**
	 * Returns a set with client's password as new information.
	 * @param oldArgs: The outdated set of information.
	 * @param password: The password to be added to the set.
	 */
	public static String[] getNewArgs(String[] oldArgs, String password) {
		String[] newArgs = new String[oldArgs.length + 2];
		
		for(int i = 0; i < 4; i++) {
			newArgs[i] = oldArgs[i];
		}
		
		// Adds client's password to the new set.
		newArgs[4] = "-p";
		newArgs[5] = password;
		
		for(int i = 6; i < newArgs.length; i++) {
			newArgs[i] = oldArgs[i - 2];
		}
		
		return newArgs;
	}
	
	/**
	 * Receives the necessary information from the server in order to 
	 * download desired document, downloading it and prompting appropriate message.
	 * @param inStream: The input stream used for receiving information from the server.
	 * @param documentSize: The size of the document to be received.
	 */
	public static void downloadDocument(ObjectInputStream inStream, Long documentSize) throws Exception {
		String documentName = (String) inStream.readObject();
		
		String userID = (String) inStream.readObject();
		
		File document = new File("clientRepository/" + documentName);
		
		// Checks if document name is already being used.
		// If so renames it by adding _i. 
		if(document.exists()) {
			List<String> splitDocumentName = new ArrayList<String>(Arrays.asList(documentName.split("\\.")));
			int numFile = 1;
			File provDocument = new File("clientRepository/" + splitDocumentName.get(0) 
										 + "_" + numFile + "." + splitDocumentName.get(1));
				
			while(provDocument.exists()) {
				numFile++;
				provDocument = new File("clientRepository/" + splitDocumentName.get(0) 
										+ "_" + numFile + "." + splitDocumentName.get(1));
			}
			
			// Renaming will be done here.
			documentName = provDocument.getName();
		}
			
		FileOutputStream outDocument = new FileOutputStream("clientRepository/" + documentName);
			
		BufferedOutputStream outDocumentBuff = new BufferedOutputStream(outDocument);
			
		byte[] buffer = new byte[2048];
		int bytesRead;
		
		// Retrieves document from server and creates new one 
		// on the client's repository.
		while(documentSize > 0) {
			bytesRead = inStream.read(buffer, 0, (int) (documentSize < 2048 ? documentSize : 2048));
			outDocumentBuff.write(buffer, 0, bytesRead);
			documentSize = documentSize - bytesRead;
		}
			
		outDocumentBuff.close();
		outDocument.close();
		
		byte[] uploaderSignature = new byte[256];
		
		inStream.read(uploaderSignature, 0, 256);
		String uploaderSignatureFileName = (String) inStream.readObject();
		
		// Obtain the actual uploader's certificate from the client's keystore.
		Certificate uploaderCertificate = getUploaderCertificate(uploaderSignatureFileName, userID);
		
		boolean isCorrectSignature = verifySignature(uploaderSignature, documentName, uploaderCertificate);
		
		if(isCorrectSignature) {
			System.out.println("O ficheiro " + documentName + " foi recebido pelo cliente.");
		}
		
		else {
			document = new File("clientRepository/" + documentName);
			document.delete();
			
			System.out.println("ERRO! Assinatura digital inválida.");
		}
	}
	
	
	/**
	 * Sends the necessary information to the server in order for him to 
	 * upload desired document, if the document exists in the client's repository.
	 * Otherwise prompts appropriate error message.
	 * @param outStream: The output stream used for sending information to the server.
	 * @param inStream: The input stream used for receiving information from the server. 
	 */
	public static void uploadDocument(ObjectOutputStream outStream, ObjectInputStream inStream) throws Exception {
		String documentName = (String) inStream.readObject();
		String userToUploadToName = (String) inStream.readObject();
		String userToUploadTo = (String) inStream.readObject();
		String userID = (String) inStream.readObject();
		
		File document = new File("clientRepository/" + documentName);
		
		// Checks if document to be sent actually exists.
		if(document.exists()) {
			outStream.writeObject((Boolean) true);
				
			Long documentSize = (Long) document.length();
			outStream.writeObject(documentSize);
				
			FileInputStream inDocument = new FileInputStream(document);
				
			BufferedInputStream inDocumentBuff = new BufferedInputStream(inDocument);
				
			byte[] buffer = new byte[2048];
			int bytesRead;
				
			while( (bytesRead = inDocumentBuff.read(buffer, 0, 2048)) > 0) {
				outStream.write(buffer, 0, bytesRead);
			}
				
			inDocumentBuff.close();
			inDocument.close();
			
			// Obtains client's private key.
			Key privateKey = getPrivateKey(userID);
			
			// Signs the sent document in order to generate a signature to be sent.
			Signature signature = signDocument(document, privateKey);
			
		    // Sends signature to server.
		    outStream.writeObject(signature.sign());
			
			System.out.println("O ficheiro " + documentName + " foi enviado para o servidor"
							   + " e ficou associado ao utilizador " + userToUploadToName
							   + " com o id " + userToUploadTo);
		}
			
		else {
			outStream.writeObject((Boolean) false);
			System.out.println("ERRO! O documento a dar upload não existe.");
		}
	}
	
	/**
	 * Retrieves the client's private key from its keystore.
	 * @param userID: The ID of the client.
	 */
	public static Key getPrivateKey(String userID) throws Exception {
		FileInputStream keyStoreFile = new FileInputStream("keyStores/keystore." + userID);
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(keyStoreFile, "123456".toCharArray());
		Key privateKey = keyStore.getKey("user" + userID, "123456".toCharArray());
		
		return privateKey;
	}
	
	
	/**
	 * Retrieves the certificate of the user who uploaded the document 
	 * to the server from the client's keystore.
	 * @param uploaderSignatureFileName: The name of file where the uploader's signature is located.
	 * @param userID: The ID of the client.
	 */
	public static Certificate getUploaderCertificate(String uploaderSignatureFileName, String userID) throws Exception {
		List<String> splitUploaderSignatureFileName = new ArrayList<String>(Arrays.asList(uploaderSignatureFileName.split("\\.")));
		String uploaderUserID = splitUploaderSignatureFileName.get(3);
		
		//Access downloader's keystore.
		FileInputStream keyStoreFile = new FileInputStream("keyStores/keystore." + userID);
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(keyStoreFile, "123456".toCharArray());
		Certificate uploaderCertificate = keyStore.getCertificate("user" + uploaderUserID);
		
		return uploaderCertificate;
	}
	
	
	/**
	 * Retrieves user's digital signature by signing the document that was sent to be uploaded.
	 * @param document: The document that was sent to be uploaded.
	 * @param privateKey: The user's private key to be used on signing the document.
	 */
	public static Signature signDocument(File document, Key privateKey) throws Exception {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign((PrivateKey) privateKey);
		
		FileInputStream inDocument = new FileInputStream(document);
		
	    byte[] buffer = new byte[2048];
	    
	    int bytesRead = inDocument.read(buffer);
	    
	    while(bytesRead != -1) {
	    	signature.update(buffer, 0, bytesRead);
	    	bytesRead = inDocument.read(buffer);
	    }
	    
	    inDocument.close();
	    
	    return signature;
	}
	
	
	/**
	 * Verifies if uploader's signature matches with actual user's signature.
	 * @param uploaderSignature: The uploader's signature.
	 * @param documentName: The name of the document to be hashed.
	 * @param uploaderCertificate: The actual user's signature.
	 */
	public static boolean verifySignature(byte[] uploaderSignature, String documentName, Certificate uploaderCertificate) throws Exception {
		Signature mySignature = Signature.getInstance("SHA256withRSA");
		mySignature.initVerify(uploaderCertificate);
		
		FileInputStream inDocument = new FileInputStream("clientRepository/" + documentName);
		
	    byte[] buffer = new byte[2048];
	    
	    int bytesRead = inDocument.read(buffer);
	    
	    while(bytesRead != -1) {
	    	mySignature.update(buffer, 0, bytesRead);
	    	bytesRead = inDocument.read(buffer);
	    }
	    
	    inDocument.close();
	    
	    boolean isCorrectSignature = mySignature.verify(uploaderSignature);
	    
	    return isCorrectSignature;
	}
}