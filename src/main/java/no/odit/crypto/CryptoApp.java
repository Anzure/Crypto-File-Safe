package no.odit.crypto;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.model.enums.AesKeyStrength;
import net.lingala.zip4j.model.enums.EncryptionMethod;
import no.odit.crypto.model.EncryptionDetails;
import no.odit.crypto.model.PuzzleDetails;
import no.odit.crypto.type.ActionType;
import no.odit.crypto.util.AES;
import no.odit.crypto.util.MachineUtil;
import no.odit.crypto.util.TimeLockPuzzle;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;
import java.util.Scanner;

public class CryptoApp {

    public static String APPLICATION_ID = "tSaNPCqcs0YSxdbW";
    private static String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static Scanner scanner = new Scanner(System.in);

    public static void main(String... args) throws Exception {

        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.findAndRegisterModules();
        File detailsFile = new File("capsule.json");
        if (detailsFile.exists()) detailsFile.delete();

        System.out.println("Choose an action:");
        System.out.println("1 - Encrypt a file");
        System.out.println("2 - Decrypt a file");
        System.out.print("Enter action: ");
        Integer actionInput = Integer.parseInt(scanner.nextLine());
        ActionType actionType = ActionType.values()[actionInput - 1];

        if (actionType == ActionType.ENCRYPT_FILE) {

            System.out.print("Enter file name: ");
            String fileName = scanner.nextLine();
            File contentFile = new File(fileName);
            if (!contentFile.exists()) {
                System.out.println("The file do not exist!");
                return;
            }

            System.out.print("Enter seconds: ");
            BigInteger duration = new BigInteger(scanner.nextLine());

            System.out.print("Enter passphrase: ");
            String passphrase = scanner.nextLine();

            System.out.println("Preparing files...");
            File encryptedFile = new File(contentFile.getName() + ".aes");
            File compressedFile = new File(contentFile.getName() + ".zip");

            System.out.println("Deleting old files...");
            if (encryptedFile.exists()) encryptedFile.delete();
            if (compressedFile.exists()) compressedFile.delete();
            if (detailsFile.exists()) detailsFile.delete();

            System.out.println("Hashing password...");
            long startTime = System.currentTimeMillis();
            String machineId = MachineUtil.getMachineIdentifier();
            byte[] machineIdBytes = machineId.getBytes(StandardCharsets.UTF_8);
            byte[] applicationIdBytes = APPLICATION_ID.getBytes(StandardCharsets.UTF_8);
            String salt = new String(BCrypt.withDefaults().hash(14, applicationIdBytes, machineIdBytes), StandardCharsets.UTF_8);
            byte[] saltBytes = salt.substring(16, 32).getBytes(StandardCharsets.UTF_8);
            byte[] passphraseBytes = passphrase.getBytes(StandardCharsets.UTF_8);
            String password = new String(BCrypt.withDefaults().hash(14, saltBytes, passphraseBytes), StandardCharsets.UTF_8);
            long endTime = System.currentTimeMillis();
            long time = endTime - startTime;
            System.out.println("Hashed password in " + time + "ms.");

            System.out.println("Generating keys...");
            startTime = System.currentTimeMillis();
            IvParameterSpec iv = AES.generateIv();
            String encodedIv = AES.encodeIvParameterSpec(iv);
            SecretKey secretKey = AES.generateKey(256);
            String encodedSecretKey = AES.encodeSecretKey(secretKey);
            secretKey = AES.decodeSecretKey(encodedSecretKey);
            endTime = System.currentTimeMillis();
            time = endTime - startTime;
            System.out.println("Generated keys in " + time + "ms.");

            System.out.println("Creating puzzle...");
            startTime = System.currentTimeMillis();
            PuzzleDetails puzzle = TimeLockPuzzle.createPuzzle(encodedSecretKey, duration);
            endTime = System.currentTimeMillis();
            time = endTime - startTime;
            System.out.println("Puzzle created in " + time + "ms.");

            System.out.println("Encrypting file...");
            startTime = System.currentTimeMillis();
            EncryptionDetails result = encryptFile(contentFile, encryptedFile, secretKey, iv);
            endTime = System.currentTimeMillis();
            time = endTime - startTime;
            System.out.println("Encrypted file in " + time + "ms.");

            System.out.println("Creating details file...");
            result.setIvParameterSpec(encodedIv);
            result.setN(puzzle.getN());
            result.setT(puzzle.getT());
            result.setZ(puzzle.getZ());
            result.setSalt(salt);
            result.setMachineId(machineId);
            result.setApplicationId(APPLICATION_ID);
            result.setZipKey(password);
            objectMapper.writeValue(detailsFile, result);

            System.out.println("Deleting unencrypted file...");
            contentFile.delete();

            System.out.println("Compressing files...");
            startTime = System.currentTimeMillis();
            List<File> files = List.of(encryptedFile, detailsFile);
            compressFiles(files, compressedFile, password);
            endTime = System.currentTimeMillis();
            time = endTime - startTime;
            System.out.println("Compressed files in " + time + "ms.");

            System.out.println("Completed encryption task!");

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

            System.out.println("Hashing password...");
            long startTime = System.currentTimeMillis();
            String machineId = MachineUtil.getMachineIdentifier();
            byte[] machineIdBytes = machineId.getBytes(StandardCharsets.UTF_8);
            byte[] applicationIdBytes = APPLICATION_ID.getBytes(StandardCharsets.UTF_8);
            String salt = new String(BCrypt.withDefaults().hash(14, applicationIdBytes, machineIdBytes), StandardCharsets.UTF_8);
            byte[] saltBytes = salt.substring(16, 32).getBytes(StandardCharsets.UTF_8);
            byte[] passphraseBytes = passphrase.getBytes(StandardCharsets.UTF_8);
            String password = new String(BCrypt.withDefaults().hash(14, saltBytes, passphraseBytes), StandardCharsets.UTF_8);
            long endTime = System.currentTimeMillis();
            long time = endTime - startTime;
            System.out.println("Hashed password in " + time + "ms.");

            System.out.println("Extracting files...");
            startTime = System.currentTimeMillis();
            extractFiles(compressedFile, password);
            endTime = System.currentTimeMillis();
            time = endTime - startTime;
            System.out.println("Extracted files in " + time + "ms.");

            System.out.println("Reading details...");
            EncryptionDetails details = objectMapper.readValue(detailsFile, EncryptionDetails.class);
            File contentFile = new File(details.getFileName());
            File encryptedFile = new File(contentFile.getName() + ".aes");
            IvParameterSpec iv = AES.decodeIvParameterSpec(details.getIvParameterSpec());

            System.out.println("Solving puzzle... (this may take a while!)");
            startTime = System.currentTimeMillis();
            String secret = TimeLockPuzzle.solvePuzzle(details.getN(), details.getT(), details.getZ());
            endTime = System.currentTimeMillis();
            time = endTime - startTime;
            System.out.println("Solved puzzle in " + (time / 1000) + "s.");

            System.out.println("Parsing secret key...");
            SecretKey secretKey = AES.decodeSecretKey(secret);

            System.out.println("Decrypting file...");
            startTime = System.currentTimeMillis();
            AES.decryptFile(AES_ALGORITHM, secretKey, iv, encryptedFile, contentFile);
            endTime = System.currentTimeMillis();
            time = endTime - startTime;
            System.out.println("Decrypted file in " + time + "ms.");

            System.out.println("Deleting details file...");
            detailsFile.delete();

            System.out.println("Deleting encrypted file...");
            encryptedFile.delete();

            System.out.println("Deleting compressed file...");
            compressedFile.delete();


            System.out.println("Completed decryption task!");
        }
    }

    private static void extractFiles(File file, String passphrase) throws Exception {
        ZipFile zipFile = new ZipFile(file, passphrase.toCharArray());
        zipFile.extractAll(".");
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

    private static EncryptionDetails encryptFile(File inputFile, File outputFile, SecretKey secretKey, IvParameterSpec iv) {
        try {


            // Encrypt file
            AES.encryptFile(AES_ALGORITHM, secretKey, iv, inputFile, outputFile);

            // Debug


            // Return result
            return EncryptionDetails.builder()
                    .fileName(inputFile.getName())
                    .date(LocalDate.now())
                    .time(LocalTime.now())
                    .build();

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void decryptFile(File inputFile, File outputFile, SecretKey secretKey, IvParameterSpec iv) {
        try {


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}