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

        if (actionType == ActionType.ENCRYPT_FILE) {

            System.out.print("Enter file name: ");
            String fileName = scanner.nextLine();
            File contentFile = new File(fileName);
            if (!contentFile.exists()) {
                System.out.println("The file do not exist!");
                return;
            }

            System.out.print("Enter seconds: ");
            Integer duration = Integer.parseInt(scanner.nextLine()) * 1000;

            System.out.print("Enter passphrase: ");
            String passphrase = scanner.nextLine();

            KeyPair keys = RSA.generateKeys();

            File encryptedFile = new File(contentFile.getName() + ".rsa");
            File compressedFile = new File(contentFile.getName() + ".zip");
            if (encryptedFile.exists()) encryptedFile.delete();
            if (compressedFile.exists()) compressedFile.delete();
            if (detailsFile.exists()) detailsFile.delete();

            EncryptionDetails result = encryptFile(contentFile, encryptedFile, keys.getPublic(), duration);
            result.setPrivateKey(RSA.savePrivateKey(keys.getPrivate()));
            contentFile.delete();
            objectMapper.writeValue(detailsFile, result);

            List<File> files = List.of(encryptedFile, detailsFile);
            compressFiles(files, compressedFile, passphrase);

        } else if (actionType == ActionType.DECRYPT_FILE) {

            System.out.print("Enter file name: ");
            String fileName = scanner.nextLine();
            File compressedFile = new File(fileName);
            if (!compressedFile.exists()) {
                System.out.println("The file do not exist!");
                return;
            }

            System.out.print("Enter passphrase: ");
            String passphrase = scanner.nextLine();

            extractFiles(compressedFile, passphrase);

            EncryptionDetails details = objectMapper.readValue(detailsFile, EncryptionDetails.class);
            Integer difficulty = details.getDifficulty();
            File contentFile = new File(details.getFileName());
            File encryptedFile = new File(contentFile.getName() + ".rsa");
            PrivateKey privateKey = RSA.loadPrivateKey(details.getPrivateKey());

            decryptFile(encryptedFile, contentFile, privateKey, difficulty);
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

    private static EncryptionDetails encryptFile(File file, File target, PublicKey publicKey, long duration) {
        try (FileOutputStream outputStream = new FileOutputStream(target);
             FileInputStream inputStream = new FileInputStream(file)) {
            long startTime = System.currentTimeMillis();
            long targetTime = startTime + duration;

            // Handle bytes
            int blockSize = 501;
            long blocksNeeded = ((file.length()) / blockSize);
            int difficulty = 0;

            System.out.println("Blocks needed: " + blocksNeeded);

            // Encrypt blocks

            while (System.currentTimeMillis() < targetTime) {
                byte[] bytes = inputStream.readAllBytes();
                for (int i = 0; i <= blocksNeeded; i++) {
                    // Read a chunk of bytes
                    int currentBlockSize = i != blocksNeeded ? blockSize : (int) (file.length() - (blocksNeeded * blockSize));
                    byte[] block = new byte[currentBlockSize];

                    for (int x = 0; x < currentBlockSize; x++){
                        int offset = (int) (blocksNeeded * blockSize);
                        block[x] = bytes[x + offset];
                    }
                    inputStream.read(block, 0, blockSize);

                    // Write encrypted data
                    byte[] encrypted = RSA.encrypt(block, publicKey);

                    for (int x = 0; x < difficulty; x++) {
                        encrypted = RSA.encrypt(block, publicKey);
                    }

                    outputStream.write(encrypted);
                    System.out.println("Test");
                }
            }

            System.out.println("Difficulty: " + difficulty);

//            // Encrypt last block
//            if (file.length() > blocksNeeded * blockSize) {
//                // Read last chunk of bytes
//                blockSize = (int) (file.length() - (blocksNeeded * blockSize));
//                byte[] block = new byte[blockSize];
//
//                inputStream.read(block, 0, blockSize);
//
//                // Write encrypted data
//                byte[] encrypted = RSA.encrypt(block, publicKey);
//                for (int x = 0; x < difficulty; x++) {
//                    encrypted = RSA.encrypt(block, publicKey);
//                }
//
//                outputStream.write(encrypted);
//            }

            // Debug
            long endTime = System.currentTimeMillis();
            long time = endTime - startTime;
            System.out.println("Encrypted: " + file.getName() + " finished in " + time + " ms.");
            return EncryptionDetails.builder()
                    .fileName(file.getName())
                    .date(LocalDate.now())
                    .time(LocalTime.now())
                    .duration(Duration.ofMillis(time))
                    .difficulty(difficulty)
                    .publicKey(RSA.savePublicKey(publicKey))
                    .build();

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void decryptFile(File file, File target, PrivateKey privateKey, int difficulty) {
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
                for (int x = 0; x < difficulty; x++) {
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
                for (int x = 0; x < difficulty; x++) {
                    decrypted = RSA.decrypt(block, privateKey);
                }

                outputStream.write(decrypted);
            }

            // Debug
            long endTime = System.currentTimeMillis();
            long time = endTime - startTime;
            System.out.println("Decrypted: " + file.getName() + " finished in " + time + " ms.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}