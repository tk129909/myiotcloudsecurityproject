package EncryDecry;

import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;

public class NewEncryDecryWinAPP {

private Cipher cipher;
	
	//for AES
	private SecretKeySpec secretKey;
	//
	//for DES
	private Cipher desCipher;
	private KeyGenerator keygenerator;
    private SecretKey myDesKey;
    String stringtextEncrypted;
    byte[] textEncrypted;
	//for RSA
	private KeyPairGenerator keyGen;
	private KeyPair pair;
	//private PrivateKey privateKey;
	//private PublicKey publicKey;
	private Key publicKey;
	private Key privateKey;
	//
    byte[] encryptedinRSA;	
	static NewEncryDecryWinAPP window;

	Integer choosenAlg;

	 JFrame frame;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					
					window = new NewEncryDecryWinAPP("!@#$MySecr3tPassw0rd", 16, "AES");
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public NewEncryDecryWinAPP() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		initialize();
	}
	public NewEncryDecryWinAPP(String secret, int length, String algorithm)
			throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		byte[] key = new byte[length];
		key = fixSecret(secret, length);
		this.secretKey = new SecretKeySpec(key, algorithm);
		this.cipher = Cipher.getInstance(algorithm);//for AES encrypt
		
			initialize();
		
	}

	/**
	 * Initialize the contents of the frame.
	 * @throws InvalidKeyException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 */
	private void initialize() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		frame = new JFrame();
		frame.getContentPane().setEnabled(false);
		frame.getContentPane().setLayout(null);
		
		
		File dir = new File("C:\\Users\\Z-500\\Desktop\\eclipse\\workspace\\MyIoTProject\\src\\cryptodir");//File dir = new File("src/cryptodir"); 
		File[] filelist = dir.listFiles();

	    //combobox for algorithms
		
		JComboBox comboBox = new JComboBox();
		comboBox.setEditable(true);
		comboBox.addItem("AES");
		comboBox.addItem("DES");
		comboBox.addItem("RSA");
		comboBox.setVisible(true);
		//System.out.println(comboBox.getSelectedItem());
		comboBox.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                //
                // Get the source of the component, which is our combo
                // box.
                //
                JComboBox comboBox = (JComboBox) event.getSource();
                
                Object selected = comboBox.getSelectedItem();
                if(selected.toString().equals("AES")) {
                	choosenAlg=1;
                	System.out.println(selected.toString());
                }
                	
                else if(selected.toString().equals("DES")) {
                	choosenAlg=2;
                	System.out.println(selected.toString());
                }
                	
                else{
                	choosenAlg=3;
                	System.out.println(selected.toString());
                }

            }
        });
		comboBox.setBounds(154, 309, 100, 22);
		
		frame.getContentPane().add(comboBox);
		frame.setBounds(100, 100, 838, 553);
		//System.out.println(choosenAlg);
		

		//for DES
		keygenerator = KeyGenerator.getInstance("DES");
	    myDesKey = keygenerator.generateKey();
	    /* Create the cipher */
	    desCipher = Cipher.getInstance("DES");//"DES/ECB/PKCS5Padding"
	    
	    /* Initialize the cipher for encryption */
	    desCipher.init(Cipher.ENCRYPT_MODE, myDesKey);
		
		
		//Encrypt All Button
		JButton btnNewButton = new JButton("Encrypt All");
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Arrays.asList(filelist).forEach(file -> {
					try {
						if(choosenAlg == 1) {//AES
							window.AES_encryptFile(file);
							System.out.println(file.getName()+" "+"-" + (file.length()/1000) +"- bytes "); 
						
						}
						else if(choosenAlg == 2) {//DES
							String pathOfFile=file.getPath();
							byte[] text = Files.readAllBytes(Paths.get(pathOfFile));
							//System.out.println(Arrays.toString(text));
						    //System.out.println("Text [Byte Format] : " + text);
				            //System.out.println("Text : " + new String(text));
						    textEncrypted = desCipher.doFinal(text);
						    //System.out.println("Text Encryted [Byte Format]  : " + textEncrypted);
						    //Convert byte[] to String
						    stringtextEncrypted = new String(textEncrypted);
						    //System.out.println("Text Encryted : " + stringtextEncrypted);
						    //Write content to file
						    try (PrintStream out = new PrintStream(new FileOutputStream(file))) {
						        out.print(stringtextEncrypted);
						    }
						    
						    
						  
						    
						    
						    
						}
						else if(choosenAlg == 3) {//RSA
							
							String password = FileContenttoString(file);
							KeyPair keyPair = RSAKeyPair.keyPairRSA();
							publicKey = keyPair.getPublic();
							privateKey = keyPair.getPrivate();

							System.out.println("Encrypt Start");
							//System.out.println("Original: " + password);
							encryptedinRSA = RSAEncryptDecrypt.encrypt(password, privateKey);
							writeStringtoFile(file, new String(encryptedinRSA));
							System.out.println("Encrypted: " + new String(encryptedinRSA));
							System.out.println("Encrypt End");
							
							
						}
					} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
							| IOException e1) {
						System.err.println("Couldn't encrypt " + file.getName() + ": " + e1.getMessage());
					}
				});
				System.out.println("Files encrypted successfully");
			}
		});
		btnNewButton.setBounds(286, 309, 89, 23);
		frame.getContentPane().add(btnNewButton);
		//Decrypt All Button
		JButton btnDecryptAll = new JButton("Decrypt All");
		btnDecryptAll.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Arrays.asList(filelist).forEach(file -> {
					try {
						if(choosenAlg == 1) {//AES
							window.AES_decryptFile(file);
							System.out.println(file.getName() + " " + "-" + (file.length()/1000) +"- bytes "); 
						
						}
						if(choosenAlg == 2) {//DES
						    // Initialize the same cipher for decryption
						    desCipher.init(Cipher.DECRYPT_MODE, myDesKey);

						    // Decrypt the text
						    byte[] textDecrypted = desCipher.doFinal(textEncrypted);
						    stringtextEncrypted = new String(stringtextEncrypted);
						    //System.out.println("********");
						    //System.out.println("Text Encryted : " +stringtextEncrypted);
						    
						    try (PrintStream out = new PrintStream(new FileOutputStream(file))) {
						        out.print(new String(textDecrypted));
						    }
						    
						    
						    //System.out.println("Text Decryted : " + new String(textDecrypted));
						}
						if(choosenAlg == 3) {//RSA//245 byte max data size
							
							System.out.println();

							System.out.println("Decrypt Start");
							byte[] decrypted = RSAEncryptDecrypt.decrypt(encryptedinRSA, publicKey);
							writeStringtoFile(file, new String(decrypted));
							System.out.println("Decrypted: " + new String(decrypted));

						
						}
					} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
							| IOException e1) {
						System.err.println("Couldn't decrypt " + file.getName() + ": " + e1.getMessage());
					}
				});
				System.out.println("Files decrypted successfully");
			}
		});
		btnDecryptAll.setBounds(428, 309, 89, 23);
		frame.getContentPane().add(btnDecryptAll);
		//exit button
		JButton btnExit = new JButton("Exit");
		btnExit.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				System.exit(0);
			}
		});
		btnExit.setBounds(579, 309, 89, 23);
		frame.getContentPane().add(btnExit);

		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	}

    private byte[] fixSecret(String s, int length) throws UnsupportedEncodingException {
	if (s.length() < length) {
		int missingLength = length - s.length();
		for (int i = 0; i < missingLength; i++) {
			s += " ";
		}
	}
	return s.substring(0, length).getBytes("UTF-8");
}
public void AES_encryptFile(File f)
		throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
	System.out.println("Encrypting file: " + f.getName());
	this.cipher.init(Cipher.ENCRYPT_MODE, this.secretKey);
	this.writeToFile(f);
}

public void AES_decryptFile(File f)
		throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
	System.out.println("Decrypting file: " + f.getName());
	this.cipher.init(Cipher.DECRYPT_MODE, this.secretKey);
	this.writeToFile(f);
}

public void writeToFile(File f) throws IOException, IllegalBlockSizeException, BadPaddingException {
	FileInputStream in = new FileInputStream(f);
	byte[] input = new byte[(int) f.length()];
	in.read(input);

	FileOutputStream out = new FileOutputStream(f);
	byte[] output = this.cipher.doFinal(input);
	out.write(output);

	out.flush();
	out.close();
	in.close();
}
//DES

	public static byte[] writeBytesToFile(File file)
	{
	    byte[] fileBytes = new byte[(int) file.length()]; 
	    try(FileInputStream inputStream = new FileInputStream(file))
	    {
	        inputStream.read(fileBytes);
	    }
	    catch (Exception ex) 
	    {
	        ex.printStackTrace();
	    }
	    return fileBytes;
	}
//RSA
	public String FileContenttoString(File file) throws IOException{
		InputStream is = new FileInputStream(file); 
		BufferedReader buf = new BufferedReader(new InputStreamReader(is)); 
		String line = buf.readLine(); StringBuilder sb = new StringBuilder(); 
		while(line != null){ 
			sb.append(line).append("\n"); 
			line = buf.readLine(); } 
		String fileAsString = sb.toString(); 
		//System.out.println("Contents : " + fileAsString);
		return fileAsString;

		
	}
	public void writeStringtoFile(File file, String text) throws FileNotFoundException {
		try (PrintWriter out = new PrintWriter(file)) {
		    out.println(text);
		}
	}
}
