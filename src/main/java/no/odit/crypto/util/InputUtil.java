package no.odit.crypto.util;

import java.io.File;
import java.math.BigInteger;

public class InputUtil {

    public static File inputFile(String what) throws Exception {
        try {
            System.out.print("Enter " + what + ": ");
            String fileName = System.console().readLine();
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

    public static String inputSecretText(String what, int minimumLength) throws Exception {
        try {
            System.out.print("Enter " + what + ": ");
            String passphrase = new String(System.console().readPassword());
            if (passphrase.length() < minimumLength) throw new Exception("Too short " + what + "!");

            System.out.print("Confirm " + what + ": ");
            if (!passphrase.equals(new String(System.console().readPassword()))) {
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
            BigInteger bigInteger = new BigInteger(System.console().readLine());
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
        return System.console().readLine().equalsIgnoreCase("y");
    }

}
