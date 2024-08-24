package com.amazon.ata.introthreads.classroom;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Lists;
import com.google.common.collect.Multimap;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import java.io.IOException;
import java.io.Reader;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * A helper class for hashing a password and checking if it's valid.
 */
public class PasswordUtil {

    private static final int ITERATIONS = 20 * 1000; // 20,000 times
    private static final int KEY_LENGTH = 256;

// Files containing passwords to crack and hashed passwords
// 100 passwords to crack
    private static final String HACKED_DATABASE_FILE = "hackedDatabase100x10x190.csv";
    private static final String COMMON_PASSWORD_FILE = "commonPasswords100.csv";

// 1000 passwords to crack
//    private static final String HACKED_DATABASE_FILE = "hackedDatabase1Kx100x1900.csv";
//    private static final String COMMON_PASSWORD_FILE = "commonPasswords1K.csv";

// 10000 passwords to crack
//    private static final String HACKED_DATABASE_FILE = "hackedDatabase10Kx1Kx19K.csv";
//    private static final String COMMON_PASSWORD_FILE = "commonPasswords10K.csv";

    /**
     * Checks whether given plaintext password corresponds to a stored salted hash of the password.
     */
    public static boolean check(String password, String stored) throws Exception {
        final String[] saltAndPassword = stored.split("\\$");
        if (saltAndPassword.length != 2) {
            throw new IllegalStateException("The stored password have the form 'salt$hash'");
        }
        final String hashOfInput = hash(password, Base64.getDecoder().decode(saltAndPassword[0]));
        return hashOfInput.equals(saltAndPassword[1]);
    }

    /**
     * Computes a salted PBKDF2 hash of given plaintext password.
     */
    public static String hash(String password, String salt) throws Exception {
        final byte[] saltBytes = salt.getBytes();
        return Base64.getEncoder().encodeToString(saltBytes) + "$" + hash(password, saltBytes);
    }

    private static String hash(String password, byte[] salt) throws Exception {
        final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        final SecretKey key = secretKeyFactory.generateSecret(new PBEKeySpec(
            password.toCharArray(), salt, ITERATIONS, KEY_LENGTH));
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }


    /**
     * Read pairs of hashed password and user ids using that password.
     *
     * @return a multimap of hashed password and user ids suing that password.
     *          Key is the hashed password and value is all user ids suing that password
     */
    static Multimap<String, String> readHackedDatabase() {
        final Multimap<String, String> hackedHashToUserIds = ArrayListMultimap.create();

        try (Reader reader = Files.newBufferedReader(getPath(HACKED_DATABASE_FILE));
             CSVParser csvParser = new CSVParser(reader, CSVFormat.DEFAULT);) {
            for (CSVRecord csvRecord : csvParser) {
                // Accessing Values by Column Index
                final String userId = csvRecord.get(0);
                final String hash = csvRecord.get(1);
                hackedHashToUserIds.put(hash, userId);
            }
        }
        catch (IOException e) {
            throw new IllegalStateException(e);
        }

        return hackedHashToUserIds;
    }

    /**
     * Reads raw passwords from a file
     */
    static List<String> readCommonPasswords() {
        final List<String> passwords = Lists.newArrayList();

        try (Reader reader = Files.newBufferedReader(getPath(COMMON_PASSWORD_FILE));
             CSVParser csvParser = new CSVParser(reader, CSVFormat.DEFAULT);) {
            for (CSVRecord csvRecord : csvParser) {
                // Accessing Values by Column Index
                passwords.add(csvRecord.get(0));
            }
        }
        catch (IOException e) {
            throw new IllegalStateException(e);
        }

        return passwords;
    }

    /**
     * Get resource's path.
     */
    private static Path getPath(String fileName) {
        URL url = PasswordUtil.class.getClassLoader().getResource(fileName);

        if (url == null) {
            throw new IllegalStateException(
                "Could not access password file in resources! Please check with an instructor.");
        }

        try {
            return Paths.get(url.toURI());
        } catch (Exception e){
            throw new IllegalStateException(
                "Could not access password file in resources! Please check with an instructor.");
        }
    }
}
