package no.odit.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.primitives.Bytes;
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
import java.util.Arrays;
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
        System.out.println("1 - Encrypt a file");
        System.out.println("2 - Decrypt a file");
        System.out.print("Enter action: ");
        Integer actionInput = Integer.parseInt(scanner.nextLine());
        ActionType actionType = ActionType.values()[actionInput-1];

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
            int difficulty = 0;

            // Encrypt blocks
            byte[] bytes = inputStream.readAllBytes();
            do {
                int blocksNeeded = bytes.length / blockSize;
                System.out.println("Blocks needed: " + blocksNeeded);
                byte[] content = new byte[0];
                for (int i = 0; i <= blocksNeeded; i++) {
                    // Read a chunk of bytes
                    int currentBlockSize = i != blocksNeeded ? blockSize : bytes.length - blocksNeeded * blockSize;
                    if (currentBlockSize == 0) break;
                    int fromIndex = i * blockSize;
                    int toIndex = fromIndex+currentBlockSize;
                    byte[] block = Arrays.copyOfRange(bytes, fromIndex, toIndex);
                    System.out.println("Test: " + fromIndex + " | " + toIndex + " | " + currentBlockSize + " | " + i + "/" + blocksNeeded);

                    // Write encrypted data
                    byte[] encrypted = RSA.encrypt(block, publicKey);
                    content = Bytes.concat(content, encrypted);
                    System.out.println("Debug: " + encrypted.length + " | " + content.length + " | " + bytes.length);
                }
                bytes = content;
                difficulty++;
            } while (System.currentTimeMillis() < targetTime);

            // Write file
            outputStream.write(bytes);

            System.out.println("Difficulty: " + difficulty);

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

            // Decrypt blocks
            byte[] bytes = inputStream.readAllBytes();
            for (int diff = 0; diff < difficulty; diff++){
                byte[] content = new byte[0];
                long blocksNeeded = bytes.length / blockSize;
                for (int i = 0; i <= blocksNeeded; i++) {
                    // Read a chunk of bytes
                    int currentBlockSize = i != blocksNeeded ? blockSize : (int) (bytes.length - (blocksNeeded * blockSize));
                    if (currentBlockSize == 0) break;
                    int fromIndex = i * blockSize;
                    int toIndex = fromIndex+currentBlockSize;
                    byte[] block = Arrays.copyOfRange(bytes, fromIndex, toIndex);
                    System.out.println("Test: " + fromIndex + " | " + toIndex + " | " + currentBlockSize + " | " + i + "/" + blocksNeeded);

                    // Write encrypted data
                    byte[] decrypted = RSA.decrypt(block, privateKey);
                    content = Bytes.concat(content, decrypted);
                    System.out.println("Debug: " + decrypted.length + " | " + content.length + " | " + bytes.length);
                }
                bytes = content;
                System.out.println("Diff: " + diff + " | " + (diff + 1));
            }

            // Write file
            outputStream.write(bytes);

            // Debug
            long endTime = System.currentTimeMillis();
            long time = endTime - startTime;
            System.out.println("Decrypted: " + file.getName() + " finished in " + time + " ms.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}