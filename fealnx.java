
import java.io.*;
import java.util.*;


//
// LINAS JONAS ŽILINSKAS MIF VU IT 3 kursas 3 grupė
//
// FEAL-NX cipher (the Fast Data Encipherment Algorithm)
//
// You need to add arguments when running the program.
// -----------------------------------------------------
// To run encryption, use: 'java fealnx -e plainTextFileName -k keyFileName -o outputFileName'
// To run decryption, use: 'java fealnx -d outputFileName -k keyFileName -o outputFileName'
//

public class fealnx {

  // The round number (N) for FEAL data randomization

  final static int N = 32;

  public static void main(String[] args) {

    String keyFile = "";
    String inputFile = "";
    String outputFile = "";
    String action = "";

    if (args.length > 3){

      for (int i=0; i<args.length; i++){

        String argument = args[i];

        switch( argument ){

  				case "-k":  keyFile = args[i+1];
                      break;

          case "-e":  inputFile = args[i+1];
                      action = "e";
                      break;

          case "-d":  inputFile = args[i+1];
                      action = "d";
                      break;

          case "-o":  outputFile = args[i+1];
                      break;

        }
      }

    }

    if (args.length > 3){

      if (keyFile!=""){

        byte[] mainKey = hexStringToByteArray(readFile(keyFile));

        StringBuilder SB = new StringBuilder();

        if (action=="e"){

          byte[] plainText = hexStringToByteArray(readFile(inputFile));

          for (int i = 0; i<plainText.length/8; i++){
            byte[] tempText = new byte[8];
            System.arraycopy(plainText, i*8, tempText, 0, 8);

            byte[] cipherText = encryption(plainText, mainKey, N);

            for(byte aa : cipherText) {
              SB.append(String.format("%02X", aa));
            }
          }


          if (outputFile!="")
            writeToFile(outputFile, SB.toString());
          else writeToFile("encrypted.fn", SB.toString());

          SB.setLength(0);

          System.out.println("\n-----------------------------------------------------");
          System.out.println("\nYour "+inputFile+" file has been encrypted.");
          if (outputFile!="")
            System.out.println("\nEncryption output file: "+outputFile);
          else System.out.println("\nEncryption output file was not defined, output was written into: encrypted.fn");

        }

        else if (action=="d"){

          byte[] cipherText = hexStringToByteArray(readFile(inputFile));

          for (int i = 0; i<cipherText.length/8; i++){
            byte[] tempText = new byte[8];
            System.arraycopy(cipherText, i*8, tempText, 0, 8);

            byte[] decryptedText = decryption(cipherText, mainKey, N);

        		for(byte aa : decryptedText) {
        			SB.append(String.format("%02X", aa));
        		}
          }

          if (outputFile!="")
            writeToFile(outputFile, SB.toString());
          else writeToFile("decrypted.fn", SB.toString());
          SB.setLength(0);

          System.out.println("\n-----------------------------------------------------");
          System.out.println("\nThe "+inputFile+" file has been decrypted.");
          if (outputFile!="")
            System.out.println("\nDecryption output file: "+outputFile);
          else System.out.println("\nDecryption output file was not defined, output was written into: decrypted.fn");

        }

      }

      else System.out.println("The program will not work without key file. Please add '-k keyFileName' arguments");

    }

    else {

      System.out.println("\n\nYou need to add arguments when running the program.\n-----------------------------------------------------");
      System.out.println("\nArgument list for the program:");
      System.out.println("\n-e \t\t Used with input file of plain text (must be 8 bytes long hex string).");
      System.out.println("-d \t\t Used with input file of cipher text (must be 8 bytes long hex string).");
      System.out.println("-k \t\t Used with input file of key (must be 16 bytes long hex string).");
      System.out.println("-o \t\t Used with output file.");
      System.out.println("\nExample of a runnable line: \tjava fealnx -e plain.fn -k key.fn -o output.fn");

    }

	}


  public static String readFile(String filename) {
    try (BufferedReader br = new BufferedReader(new FileReader(filename))) {

        StringBuilder contentBuilder = new StringBuilder();
        String sCurrentLine;

        while ((sCurrentLine = br.readLine()) != null)
        {
            contentBuilder.append(sCurrentLine);
        }

        String plaintext = contentBuilder.toString();

        return plaintext;
    }

    catch (IOException ioe){
        System.out.print("\nInput file with this name was not found.");
        return null;
    }

  }

  public static void writeToFile(String filename, String str) {
    try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {

      writer.write(str);
      writer.close();

    }
    catch (IOException ioe) {
      System.out.println("\nFailed to create cipher text file.");
    }

  }

	public static byte[] hexStringToByteArray(String s) {

	    int len = s.length();
	    byte[] data = new byte[len / 2];

	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }

	    return data;

	}

  public static byte[] makeXOR(byte[] a, byte[] b) {

    byte[] result = new byte[Math.min(a.length, b.length)];

    for (int i = 0; i < result.length; i++) {
      result[i] = (byte) (((int) a[i]) ^ ((int) b[i]));
    }

    return result;

  }

  public static byte rotateLeft(byte bits, int shift) {
      return (byte)(((bits & 0xff) << shift) | ((bits & 0xff) >>> (8 - shift)));
  }

  public static byte[] encryption(byte[] P, byte[] Key, int numberOfRounds) {

		if(P.length == 8 && Key.length == 16 && numberOfRounds >= 0) {

      // Defining Kn[] (subKeys)

			byte[][] subKeys = generateKey(Key, numberOfRounds);

			byte[] XOR1 = {
              subKeys[numberOfRounds][0], subKeys[numberOfRounds][1],
  			      subKeys[numberOfRounds+1][0], subKeys[numberOfRounds+1][1],
      			  subKeys[numberOfRounds+2][0], subKeys[numberOfRounds+2][1],
      			  subKeys[numberOfRounds+3][0], subKeys[numberOfRounds+3][1]
      };
      byte[] XOR2 = {
                subKeys[numberOfRounds+4][0], subKeys[numberOfRounds+4][1],
                subKeys[numberOfRounds+5][0], subKeys[numberOfRounds+5][1],
                subKeys[numberOfRounds+6][0], subKeys[numberOfRounds+6][1],
                subKeys[numberOfRounds+7][0], subKeys[numberOfRounds+7][1]
      };

      // Plaintext P is separated into LN and RN of equal lengths (32 bits), i.e.,
      // (LN,RN)=P.

			P = makeXOR(P, XOR1);		//(L0, R0 ) = (L0, R0 ) ⊕ (KN, KN+1, KN+2, KN+3 )
			byte[] LN = new byte[4];
			System.arraycopy(P, 0, LN, 0, 4);
			byte[] RN = new byte[4];
			System.arraycopy(P, 4, RN, 0, 4);
			RN = makeXOR(LN, RN);		//(L0, R0 )= (L0, R0 ) ⊕ ( φ , L0 )


      // Rr = Lr-1 ⊕ f (Rr-1, Kr-1)
      // Lr = Rr-1
      // (RN , LN)= (RN , LN) ⊕ ( φ , RN)
      // φ = tempS

			for(int i = 0; i < numberOfRounds; i++) {

				LN = makeXOR(LN, F(RN,subKeys[i]));		//Rr = Lr-1 ⊕ f (Rr-1, Kr-1)
				byte[] tempS = new byte[4];
				System.arraycopy(LN, 0, tempS, 0, 4);
				System.arraycopy(RN, 0, LN, 0, 4);
				System.arraycopy(tempS, 0, RN, 0, 4);	//Lr = Rr-1

			}

			byte[] CipherText = new byte[8];

			LN = makeXOR(LN, RN);						//(RN , LN)= (RN , LN) ⊕ ( φ , RN)
			System.arraycopy(RN, 0, CipherText, 0, 4);
			System.arraycopy(LN, 0, CipherText, 4, 4);


      // (RN , LN)= (RN, LN) ⊕ (KN+4, KN+5, KN+6, KN+7)

			CipherText = makeXOR(CipherText, XOR2);		//(RN , LN)= (RN, LN) ⊕ (KN+4, KN+5, KN+6, KN+7)

      // Ciphertext is given as (RN, LN)

			return CipherText;

		} else {
			throw new IllegalArgumentException();
		}

	}

  public static byte[] decryption(byte[] CipherText, byte[] Key, int numberOfRounds) {
		if(CipherText.length == 8 && Key.length == 16 && numberOfRounds >= 0) {

      // Defining Kn[] (subKeys)

			byte[][] subKeys = generateKey(Key, numberOfRounds);

			byte[] XOR1 = {
        subKeys[numberOfRounds+4][0], subKeys[numberOfRounds+4][1],
        subKeys[numberOfRounds+5][0], subKeys[numberOfRounds+5][1],
        subKeys[numberOfRounds+6][0], subKeys[numberOfRounds+6][1],
        subKeys[numberOfRounds+7][0], subKeys[numberOfRounds+7][1]
      };
      byte[] XOR2 = {
        subKeys[numberOfRounds][0],subKeys[numberOfRounds][1],
        subKeys[numberOfRounds+1][0],subKeys[numberOfRounds+1][1],
        subKeys[numberOfRounds+2][0],subKeys[numberOfRounds+2][1],
        subKeys[numberOfRounds+3][0],subKeys[numberOfRounds+3][1]
      };

      // Ciphertext (RN, LN) is separated into RN and LN of equal lengths.

      CipherText = makeXOR(CipherText, XOR1);		//(RN , LN)= (RN, LN) ⊕ (KN+4, KN+5, KN+6, KN+7)
			byte[] LN = new byte[4];
			System.arraycopy(CipherText, 4, LN, 0, 4);
			byte[] RN = new byte[4];
			System.arraycopy(CipherText, 0, RN, 0, 4);
			LN = makeXOR(LN, RN);					//(RN , LN)= (RN, LN) ⊕ ( φ , RN)



			for(int i = numberOfRounds-1; i >= 0; i--) {
				byte[] tempS = new byte[4];
				System.arraycopy(LN, 0, tempS, 0, 4);
				System.arraycopy(RN, 0, LN, 0, 4);
				System.arraycopy(tempS, 0, RN, 0, 4);		//Rr-1 = Lr
				LN = makeXOR(LN, F(RN,subKeys[i]));			//Lr-1 = Rr ⊕ f (Lr, Kr-1)

			}

			byte[] PlainText = new byte[8];

			RN = makeXOR(LN, RN);							//(L0 , R0)= (L0, R0) ⊕ ( φ , L0)
			System.arraycopy(LN, 0, PlainText, 0, 4);
			System.arraycopy(RN, 0, PlainText, 4, 4);

      // (LN, RN)= (LN, RN) ⊕ (KN, KN+1, KN+2, KN+3)

			PlainText = makeXOR(PlainText, XOR2);			//(L0, R0)= (L0, R0) ⊕ (KN, KN+1, KN+2, KN+3)


      // Plaintext is given as (LN, RN).

			return PlainText;

		} else {
			throw new IllegalArgumentException();
		}

	}

  public static byte[][] generateKey(byte[] Key, int numberOfRounds) {

		if(Key.length == 16) {

      // 128-bit key is equally divided into a 64-bit left key, KL, and a 64-bit
      // right key, KR. (KL, KR) is the inputted 128-bit key.

			byte[][] subKeys = new byte[2*(numberOfRounds+4)][2];
			byte[] KL = new byte[4];
			System.arraycopy(Key, 0, KL, 0, 4);
			byte[] KR = new byte[4];
			System.arraycopy(Key, 4, KR, 0, 4);

      // KR is divided into left KR1 and right KR2 half , (i. e., (KR1, KR2) = KR) and the
      // temporary variable, Qr.

			byte[] tempX = new byte[4];
			byte[] Qr = new byte[4];
			byte[] KR1 = new byte[4];
			System.arraycopy(Key, 8, KR1, 0, 4);
			byte[] KR2 = new byte[4];
			System.arraycopy(Key, 12, KR2, 0, 4);
			byte[] KRX = makeXOR(KR1,KR2);

      // Processing of the right key KR

			for(int i = 0; i < 4 + numberOfRounds; i++) {

        // Qr = KR1 ⊕ KR2 for r = 1, 4, 7..., (r = 3i+1; i = 0, 1, ...)
        // Qr = KR1 for r = 2, 5, 8..., (r = 3i+2; i = 0, 1, ...)
        // Qr = KR2 for r = 3, 6, 9..., (r = 3i+3; i = 0, 1, ...)
        // where 1 ≦ r ≦ (N/2)+4, (N ≧ 32, N: even).

        switch( i % 3 ){
  				case 0: Qr = makeXOR(KR, KRX);
                  break;
  				case 1: Qr = makeXOR(KR, KR1);
                  break;
  				case 2: Qr = makeXOR(KR, KR2);
  				        break;
        }

				if(i>0) {
					Qr = makeXOR(Qr, tempX);
				}


        // Processing of the left key KL

				System.arraycopy(KL, 0, tempX, 0, 4);	//Dr = Ar-1 carryover
				KL = Fk(KL, Qr);						//Br = fK(α, β)

				System.arraycopy(KL, 0, subKeys[2*i], 0, 2);		//K2(r-1) = (Br0, Br1)
				System.arraycopy(KL, 2, subKeys[(2*i)+1], 0, 2);	//K2(r-1)+1 = (Br2, Br3)

				byte[] tempS = new byte[4];				//Ar = Br-1
				System.arraycopy(KL, 0, tempS, 0, 4);
				System.arraycopy(KR, 0, KL, 0, 4);
				System.arraycopy(tempS, 0, KR, 0, 4);
			}

			return subKeys;

		} else {
			throw new IllegalArgumentException();
		}
	}

  // α = (α0, α1, α2, α3), β = ( β0, β1, β2, β3).
  // (fK0, fK1, fK2, fK3) = fK are calculated in sequence.
  // fK1 = α1 ⊕ α0
  // fK2 = α2 ⊕ α3
  // fK1 = S1 (fK1, ( fK2 ⊕ β0 ) )
  // fK2 = S0 (fK2, ( fK1 ⊕ β1 ) )
  // fK0 = S0 (α0, ( fK1 ⊕ β2 ) )
  // fK3 = S1 (α3, ( fK2 ⊕ β3 ) ) IDEDAM 8 BAITUS, GRAZINA 4 BAITUS
  public static byte[] Fk(byte[] a, byte[] b) {
      if(a.length == 4 && 4 == b.length) {
          byte fk1 = (byte)(a[1]^a[0]);
          byte fk2 = (byte)(a[2]^a[3]);

          fk1 = S(fk1, (byte)(fk2^b[0]), (byte) 1);
          fk2 = S(fk2, (byte)(fk1^b[1]), (byte) 0);
          byte fk0 = S(a[0], (byte)(fk1^b[2]), (byte)0);
          byte fk3 = S(a[3], (byte)(fk2^b[3]), (byte)1);
          byte[] fK = {fk0, fk1, fk2, fk3};

          return fK;

      } else {
          throw new IllegalArgumentException();
      }
  }

  // α = (α0 , α1, α2, α3), β = ( β0, β1).
  // (f0, f1, f2, f3) = f are calculated in sequence.
  // f1 =α1 ⊕ β0
  // f2 =α2 ⊕ β1
  // f1 = f1 ⊕ α0
  // f2 = f2 ⊕ α3
  // f1 = S1 (f1, f2 )
  // f2 = S0 (f2, f1 )
  // f0 = S0 (α0, f1)
  // f3 = S1 (α3, f2 ) IDEDAM 6 BAITUS, GRAZINA 4 BAITUS
  public static byte[] F(byte[] a, byte[] b) {
      if(a.length == 4 && b.length == 2) {
          byte f1 = (byte)(a[1]^b[0]);
          byte f2 = (byte)(a[2]^b[1]);
          f1 = (byte)(f1^a[0]);
          f2 = (byte)(f2^a[3]);
          f1 = S(f1, f2, (byte) 1);
          f2 = S(f2, f1, (byte) 0);
          byte f0 = S(a[0], f1, (byte) 0);
          byte f3 = S(a[3], f2, (byte) 1);

          byte[] f = {f0,f1,f2,f3};

          return f;

      } else {
          throw new IllegalArgumentException();
      }
  }

  // S0(X1, X2)=Rot2((X1 + X2) mod 256)      < when D=0
  // S1(X1, X2)=Rot2((X1 + X2 + 1) mod 256)  < when D=1 SUDEDA IR PASHIFTINA
  public static byte S(byte X1, byte X2, byte D) {
      if(D == 0 || D == 1) {
          int A = X1 & 0xFF;
          int B = X2 & 0xFF;
          int de = D & 0xFF;

          byte T = (byte) ((A+B+de%256));

          T = rotateLeft(T,2);

          return T;

      } else {
          throw new IllegalArgumentException();
      }
  }

}
