package no.odit.crypto;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.model.enums.AesKeyStrength;
import net.lingala.zip4j.model.enums.EncryptionMethod;
import net.lingala.zip4j.util.FileUtils;
import no.odit.crypto.model.EncryptionDetails;
import no.odit.crypto.model.PuzzleDetails;
import no.odit.crypto.type.ActionType;
import no.odit.crypto.util.AES;
import no.odit.crypto.util.InputUtil;
import no.odit.crypto.util.TimeLockPuzzle;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalDate;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class CryptoApp {

    public static String APPLICATION_ID = "fWyDzpN64CRQrDU5";
    private static String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static String DETAILS_FILE_NAME = "capsule.json";
    private static Scanner scanner = new Scanner(System.in);

    private static List<File> deleteQueue = new ArrayList<>();

    public static void main(String... args) {

        try {

            long startTime;
            long endTime;
            long timeUsed;

            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.findAndRegisterModules();

            System.out.println("Choose an action:");
            System.out.println("1 - Encrypt a file");
            System.out.println("2 - Decrypt a file");
            System.out.print("Enter action: ");
            Integer actionInput = Integer.parseInt(scanner.nextLine());
            ActionType actionType = ActionType.values()[actionInput - 1];

            if (actionType == ActionType.ENCRYPT_FILE) {

                File contentFile = InputUtil.inputFile("file name");
                String fileName = FileUtils.getFileNameWithoutExtension(contentFile.getName());
                String fileExtension = FileUtils.getFileExtension(contentFile);
                BigInteger duration = InputUtil.inputNumber("seconds", 5);
                String passphrase = InputUtil.inputSecretText("passphrase", 8);
                BigInteger pinCode = InputUtil.inputSecretNumber("PIN code", 8);
                String password = hashPassword(passphrase, fileName);

                System.out.println("Preparing files...");
                File encryptedFile = new File(fileName + ".aes");
                File containerFile = new File(fileName + ".safe");

                System.out.println("Generating keys...");
                startTime = System.currentTimeMillis();
                IvParameterSpec iv = AES.generateIv();
                String encodedIv = AES.encodeIvParameterSpec(iv);
                SecretKey secretKey = AES.generateKey(256);
                String encodedSecretKey = AES.encodeSecretKey(secretKey);
                endTime = System.currentTimeMillis();
                timeUsed = endTime - startTime;
                System.out.println("Generated keys in " + timeUsed + "ms.");

                System.out.println("Creating puzzle...");
                startTime = System.currentTimeMillis();
                PuzzleDetails puzzle = TimeLockPuzzle.createPuzzle(encodedSecretKey, duration);
                puzzle.setZ(puzzle.getZ().add(pinCode));
                endTime = System.currentTimeMillis();
                timeUsed = endTime - startTime;
                System.out.println("Puzzle created in " + timeUsed + "ms.");

                System.out.println("Encrypting file...");
                startTime = System.currentTimeMillis();
                if (encryptedFile.exists()) encryptedFile.delete();
                AES.encryptFile(AES_ALGORITHM, secretKey, iv, contentFile, encryptedFile);
                forceDeleteFile(contentFile);
                endTime = System.currentTimeMillis();
                timeUsed = endTime - startTime;
                System.out.println("Encrypted file in " + timeUsed + "ms.");

                System.out.println("Creating details file...");
                File detailsFile = new File(DETAILS_FILE_NAME);
                if (detailsFile.exists()) detailsFile.delete();
                else detailsFile.createNewFile();
                EncryptionDetails details = EncryptionDetails.builder()
                        .fileName(fileName)
                        .fileExtension(fileExtension)
                        .date(LocalDate.now())
                        .time(LocalTime.now())
                        .ivParameterSpec(encodedIv)
                        .n(puzzle.getN())
                        .t(puzzle.getT())
                        .z(puzzle.getZ())
                        .build();
                details.setIvParameterSpec(encodedIv);
                details.setN(puzzle.getN());
                details.setT(puzzle.getT());
                details.setZ(puzzle.getZ());
                objectMapper.writeValue(detailsFile, details);

                System.out.println("Compressing files...");
                startTime = System.currentTimeMillis();
                List<File> files = List.of(encryptedFile, detailsFile);
                if (containerFile.exists()) containerFile.delete();
                compressFiles(files, containerFile, password);
                forceDeleteFile(detailsFile);
                forceDeleteFile(encryptedFile);
                endTime = System.currentTimeMillis();
                timeUsed = endTime - startTime;
                System.out.println("Compressed files in " + timeUsed + "ms.");

                System.out.println("Completed encryption task!");

            } else if (actionType == ActionType.DECRYPT_FILE) {

                File containerFile = InputUtil.inputFile("file name");
                String fileName = FileUtils.getFileNameWithoutExtension(containerFile.getName());
                String passphrase = InputUtil.inputSecretText("passphrase", 8);
                BigInteger pinCode = InputUtil.inputSecretNumber("PIN code", 8);
                String password = hashPassword(passphrase, fileName);

                System.out.println("Reading details...");
                File detailsFile = extractFile(DETAILS_FILE_NAME, containerFile, password);
                EncryptionDetails details = objectMapper.readValue(detailsFile, EncryptionDetails.class);
                forceDeleteFile(detailsFile);
                File contentFile = new File(details.getFileName() + "." + details.getFileExtension());
                IvParameterSpec iv = AES.decodeIvParameterSpec(details.getIvParameterSpec());

                System.out.println("Solving puzzle... (this may take a while!)");
                startTime = System.currentTimeMillis();
                details.setZ(details.getZ().subtract(pinCode));
                String secret = TimeLockPuzzle.solvePuzzle(details.getN(), details.getT(), details.getZ());
                endTime = System.currentTimeMillis();
                timeUsed = endTime - startTime;
                System.out.println("Solved puzzle in " + (timeUsed / 1000) + "s.");

                System.out.println("Parsing secret key...");
                SecretKey secretKey = AES.decodeSecretKey(secret);

                System.out.println("Decrypting file...");
                startTime = System.currentTimeMillis();
                File encryptedFile = extractFile(fileName + ".aes", containerFile, password);
                forceDeleteFile(containerFile);
                AES.decryptFile(AES_ALGORITHM, secretKey, iv, encryptedFile, contentFile);
                forceDeleteFile(encryptedFile);
                endTime = System.currentTimeMillis();
                timeUsed = endTime - startTime;
                System.out.println("Decrypted file in " + timeUsed + "ms.");

                System.out.println("Completed decryption task!");
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        } finally {
            deleteQueue.forEach(file -> file.delete());
        }
    }

    private static void forceDeleteFile(File file) throws Exception {
        try {
            deleteQueue.add(file);
            file.delete();
        } catch (Exception exception) {
            Files.setAttribute(file.toPath(), "dos:hidden", true);
            throw exception;
        }
    }

    private static String hashPassword(String passphrase, String fileName) {
        System.out.println("Hashing password...");
        long startTime = System.currentTimeMillis();
        byte[] fileNameBytes = fileName.getBytes(StandardCharsets.UTF_8);
        byte[] applicationIdBytes = APPLICATION_ID.getBytes(StandardCharsets.UTF_8);
        String salt = new String(BCrypt.withDefaults().hash(16, applicationIdBytes, fileNameBytes), StandardCharsets.UTF_8);
        byte[] saltBytes = salt.substring(16, 32).getBytes(StandardCharsets.UTF_8);
        byte[] passphraseBytes = passphrase.getBytes(StandardCharsets.UTF_8);
        String password = new String(BCrypt.withDefaults().hash(16, saltBytes, passphraseBytes), StandardCharsets.UTF_8);
        long endTime = System.currentTimeMillis();
        long time = endTime - startTime;
        System.out.println("Hashed password in " + time + "ms.");
        return password;
    }

    private static File extractFile(String targetFileName, File targetZipFile, String passphrase) throws Exception {
        File targetFile = new File(targetFileName);
        if (targetFile.exists()) targetFile.delete();
        ZipFile zipFile = new ZipFile(targetZipFile, passphrase.toCharArray());
        zipFile.extractFile(targetFileName, ".");

        return targetFile;
    }

    private static void compressFiles(List<File> files, File target, String passphrase) throws Exception {
        ZipFile zipFile = new ZipFile(target, passphrase.toCharArray());
        ZipParameters zipParameters = new ZipParameters();
        zipParameters.setEncryptFiles(true);
        zipParameters.setEncryptionMethod(EncryptionMethod.AES);
        zipParameters.setAesKeyStrength(AesKeyStrength.KEY_STRENGTH_256);
        zipFile.addFiles(files, zipParameters);
    }

}