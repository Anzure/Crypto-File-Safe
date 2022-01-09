package no.odit.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.model.enums.AesKeyStrength;
import net.lingala.zip4j.model.enums.EncryptionMethod;
import no.odit.crypto.model.EncryptionDetails;
import no.odit.crypto.type.ActionType;
import no.odit.crypto.util.RSA;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;
import java.util.Scanner;

public class CryptoApp {

    private static int ADDITIONAL_ROUNDS;

    private static Scanner scanner = new Scanner(System.in);

    public static void main(String... args) throws Exception {

        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.findAndRegisterModules();
        File detailsFile = new File("details.json");
        if (detailsFile.exists()) detailsFile.delete();

        System.out.println("Choose an action:");
        System.out.println("0 - Encrypt a file");
        System.out.println("1 - Decrypt a file");
        System.out.print("Enter action: ");
        Integer actionInput = Integer.parseInt(scanner.nextLine());
        ActionType actionType = ActionType.values()[actionInput];

        System.out.print("Enter difficulty: ");
        ADDITIONAL_ROUNDS = Integer.parseInt(scanner.nextLine());

        if (actionType == ActionType.ENCRYPT_FILE) {

            System.out.print("Enter file name: ");
            String fileName = scanner.nextLine();

            KeyPair keys = RSA.generateKeys();

            File contentFile = new File(fileName);
            File encryptedFile = new File(contentFile.getName() + ".rsa");
            File compressedFile = new File(contentFile.getName() + ".zip");
            if (encryptedFile.exists()) encryptedFile.delete();
            if (compressedFile.exists()) compressedFile.delete();
            if (detailsFile.exists()) detailsFile.delete();

            long encryptionTime = encryptFile(contentFile, encryptedFile, keys.getPublic());
            contentFile.delete();
            EncryptionDetails details = EncryptionDetails.builder()
                    .fileName(contentFile.getName())
                    .date(LocalDate.now())
                    .time(LocalTime.now())
                    .duration(Duration.ofMillis(encryptionTime))
                    .publicKey(RSA.savePublicKey(keys.getPublic()))
                    .privateKey(RSA.savePrivateKey(keys.getPrivate()))
                    .build();
            objectMapper.writeValue(detailsFile, details);

            List<File> files = List.of(encryptedFile, detailsFile);
            compressFiles(files, compressedFile, "password");

        } else if (actionType == ActionType.DECRYPT_FILE) {

            System.out.print("Enter file name: ");
            String fileName = scanner.nextLine();

            File compressedFile = new File(fileName);
            extractFiles(compressedFile, "password");

            EncryptionDetails details = objectMapper.readValue(detailsFile, EncryptionDetails.class);

            File contentFile = new File(details.getFileName());
            File encryptedFile = new File(contentFile.getName() + ".rsa");

            PrivateKey privateKey = RSA.loadPrivateKey(details.getPrivateKey());

            decryptFile(encryptedFile, contentFile, privateKey);
            detailsFile.delete();
            encryptedFile.delete();
        }
    }

    private static void extractFiles(File file, String passphrase) throws Exception {
        ZipFile zipFile = new ZipFile(file, passphrase.toCharArray());
        zipFile.extractAll(".");
        file.delete();
    }

    private static void compressFiles(List<File> files, File target, String passphrase) throws Exception {
        ZipFile zipFile = new ZipFile(target, passphrase.toCharArray());
        ZipParameters zipParameters = new ZipParameters();
        zipParameters.setEncryptFiles(true);
        zipParameters.setEncryptionMethod(EncryptionMethod.AES);
        zipParameters.setAesKeyStrength(AesKeyStrength.KEY_STRENGTH_256);
        zipFile.addFiles(files, zipParameters);
        files.forEach(file -> file.delete());
    }

    private static long encryptFile(File file, File target, PublicKey publicKey) {
        try (FileOutputStream outputStream = new FileOutputStream(target);
             FileInputStream inputStream = new FileInputStream(file)) {
            long startTime = System.currentTimeMillis();

            // Handle bytes
            int blockSize = 501;
            long blocksNeeded = ((file.length()) / blockSize);

            // Encrypt blocks
            for (int i = 0; i <= blocksNeeded - 1; i++) {
                // Read a chunk of bytes
                byte[] block = new byte[blockSize];

                inputStream.read(block, 0, blockSize);

                // Write encrypted data
                byte[] encrypted = RSA.encrypt(block, publicKey);
                for (int x = 0; x < ADDITIONAL_ROUNDS; x++) {
                    encrypted = RSA.encrypt(block, publicKey);
                }

                outputStream.write(encrypted);
            }

            // Encrypt last block
            if (file.length() > blocksNeeded * blockSize) {
                // Read last chunk of bytes
                blockSize = (int) (file.length() - (blocksNeeded * blockSize));
                byte[] block = new byte[blockSize];

                inputStream.read(block, 0, blockSize);

                // Write encrypted data
                byte[] encrypted = RSA.encrypt(block, publicKey);
                for (int x = 0; x < ADDITIONAL_ROUNDS; x++) {
                    encrypted = RSA.encrypt(block, publicKey);
                }

                outputStream.write(encrypted);
            }

            // Debug
            long endTime = System.currentTimeMillis();
            long time = endTime - startTime;
            System.out.println("Encrypted: " + file.getName() + " finished in " + time + " ms.");
            return time;

        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    private static long decryptFile(File file, File target, PrivateKey privateKey) {
        try (FileOutputStream outputStream = new FileOutputStream(target);
             FileInputStream inputStream = new FileInputStream(file)) {
            long startTime = System.currentTimeMillis();

            // Handle bytes
            int blockSize = 512;
            long blocksNeeded = ((file.length()) / blockSize);

            // Decrypt blocks
            for (int i = 0; i <= blocksNeeded - 1; i++) {
                // Read a chunk of bytes
                byte[] block = new byte[blockSize];

                inputStream.read(block, 0, blockSize);

                // Write encrypted data
                byte[] decrypted = RSA.decrypt(block, privateKey);
                for (int x = 0; x < ADDITIONAL_ROUNDS; x++) {
                    decrypted = RSA.decrypt(block, privateKey);
                }

                outputStream.write(decrypted);
            }

            // Decrypt last block
            if (file.length() > blocksNeeded * blockSize) {
                // Read last chunk of bytes
                blockSize = (int) (file.length() - (blocksNeeded * blockSize));
                byte[] block = new byte[blockSize];

                inputStream.read(block, 0, blockSize);

                // Write encrypted data
                byte[] decrypted = RSA.decrypt(block, privateKey);
                for (int x = 0; x < ADDITIONAL_ROUNDS; x++) {
                    decrypted = RSA.decrypt(block, privateKey);
                }

                outputStream.write(decrypted);
            }

            // Debug
            long endTime = System.currentTimeMillis();
            long time = endTime - startTime;
            System.out.println("Decrypted: " + file.getName() + " finished in " + time + " ms.");
            return time;

        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

}