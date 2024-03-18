package no.odit.crypto.util;

import java.io.File;
import java.math.BigInteger;

import static no.odit.crypto.CryptoApp.scanner;

public class InputUtil {

    public static File inputFile(String what) throws Exception {
        try {
            System.out.print("Enter " + what + ": ");
            String fileName = scanner.nextLine();
            File contentFile = new File(fileName);
            if (!contentFile.exists()) {
                throw new Exception("The " + what + " do not exist!");
            }
            return contentFile;

        } catch (Exception exception) {
            System.out.println(exception.getMessage());
            if (inputRetry()) {
                return inputFile(what);
            } else throw exception;
        }
    }

    private static String inputHiddenText() {
        return System.console() == null ? scanner.nextLine() : new String(System.console().readPassword());
    }

    public static String inputSecretText(String what, int minimumLength) throws Exception {
        try {
            if (System.console() == null) {
                System.out.println("Warning: Unable to hide secret input from console!");
            }

            System.out.print("Enter " + what + ": ");
            String passphrase = inputHiddenText();
            if (passphrase.length() < minimumLength) throw new Exception("Too short " + what + "!");

            System.out.print("Confirm " + what + ": ");
            String confirm = inputHiddenText();
            if (!passphrase.equals(confirm)) {
                throw new Exception("The " + what + "s do not match!");
            }
            return passphrase;

        } catch (Exception exception) {
            System.out.println(exception.getMessage());
            if (inputRetry()) {
                return inputSecretText(what, minimumLength);
            } else throw exception;
        }
    }

    public static BigInteger inputSecretNumber(String what, int minimumLength) throws Exception {
        try {
            return new BigInteger(inputSecretText(what, minimumLength));
        } catch (Exception exception) {
            System.out.println(exception.getMessage());
            if (inputRetry()) {
                return inputSecretNumber(what, minimumLength);
            } else throw exception;
        }
    }

    public static BigInteger inputNumber(String what, long minimumLength) throws Exception {
        try {
            System.out.print("Enter " + what + ": ");
            BigInteger bigInteger = new BigInteger(scanner.nextLine());
            if (bigInteger.longValueExact() < minimumLength) throw new Exception("Too short " + what + "!");
            return bigInteger;
        } catch (Exception exception) {
            System.out.println(exception.getMessage());
            if (inputRetry()) {
                return inputNumber(what, minimumLength);
            } else throw exception;
        }
    }

    public static boolean inputRetry() {
        System.out.print("Do you want to try again? (Y/n): ");
        return scanner.nextLine().equalsIgnoreCase("y");
    }

}
