package com.amazon.ata.introthreads.classroom;

import com.google.common.collect.Multimap;

import java.util.List;
import java.util.Map;

/**
 * App used to crack passwords.
 */
public class PasswordCracker {

    /**
     * Main method that generates hashes for common passwords and checkes the hacked databases for any users
     * using these common passwords. Prints out any cracked passwords for the users in the database.
     */
    public static void main(String[] args) throws InterruptedException {

        long startTime = System.currentTimeMillis();

        // List of all passwords to hash - loaded from a file defined in PasswordUtil
        final List<String> commonPasswords = PasswordUtil.readCommonPasswords();

        // Call generateAll Hashes in the PasswordHasher with the list of passwords
        final Map<String, String> passwordToHashes = PasswordHasher.generateAllHashes(commonPasswords);

        PasswordHasher.writePasswordsAndHashes(passwordToHashes);

        final Multimap<String, String> hackedHashToUserIds = PasswordUtil.readHackedDatabase();

        int count = 0;
        for (Map.Entry<String, String> passwordToHash : passwordToHashes.entrySet()) {
            final String password = passwordToHash.getKey();
            final String hash = passwordToHash.getValue();

            if (hackedHashToUserIds.containsKey(hash)) {
                count += hackedHashToUserIds.get(hash).size();
                System.out.println(String.format("Users %s are using the password %s", hackedHashToUserIds.get(hash), password));
            }
        }

        System.out.println(String.format("We found the password for %d users", count));
        System.out.println("Total time elapsed: " + (System.currentTimeMillis() - startTime) + " milleseconds");
    }
}
