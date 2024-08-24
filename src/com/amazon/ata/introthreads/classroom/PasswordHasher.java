package com.amazon.ata.introthreads.classroom;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A class to pre-compute hashes for all common passwords to speed up cracking the hacked database.
 *
 * Passwords are downloaded from https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials
 */
public class PasswordHasher {
    // should create the file in your workspace directory
    private static final String PASSWORDS_AND_HASHES_FILE = "./passwordsAndHashesOutput.csv";

    // A "salt" is a value included in the hashing/encrypting process to make it harder to decrypt the value
    // Normally, a "salt" is a long String of random values - 64, 128, 512, 1024, 2048 char salts are common
    private static final String DISCOVERED_SALT = "salt"; // This is a bad salt value! (It's a constant/not random and it's short)

    /**
     * Generates hashes for all of the given passwords.
     *
     * @param passwords List of passwords to hash
     * @return map of password to hash
     * @throws InterruptedException
     */
    public static Map<String, String> generateAllHashes(List<String> passwords) throws InterruptedException {
        // Hold the final result of all hashed passwords
        Map<String, String> passwordToHashes = Maps.newConcurrentMap();

        // Replaced the call to a single BatchPasswordHasher to multi-threaded, concurrent calls
        //BatchPasswordHasher batchHasher = new BatchPasswordHasher(passwords, DISCOVERED_SALT);
        //batchHasher.hashPasswords();
        //passwordToHashes.putAll(batchHasher.getPasswordToHashes());

        // Split the list of words into sublists to give to each Thread
        List<List <String>> passwordSublist = Lists.partition(passwords, passwords.size() / 4); // We have 4 threads

        // Since the hashed passwords are inside the BatchPasswordHasher
        // and the BatchPasswordHasher will be destroyed when the Thread is done
        // we will store each BatchPasswordHasher so it will exist when the Thread is done
        // so we can copy its hashed passwords for our final set of hashed passwords
        List<BatchPasswordHasher> savedHashers = new ArrayList<>();

        // Since a Thread is destroyed when it's done
        // and we need to wait for all threads to complete before we can merge results
        // We will store the Threads so we can reference them in the waitForThreadsToComplete() method
        List<Thread> theThreads = new ArrayList<>();

        // Loop through the sublists of passwords and start a BatchPasswordHasher for each one
        for (int i = 0; i < passwordSublist.size(); i++) {
            // Instantiate a BatchPasswordHasher with a sublist and the "salt" value to use
            BatchPasswordHasher aHasher = new BatchPasswordHasher(passwordSublist.get(i), DISCOVERED_SALT);
            // Save the new BatchPasswordHasher in a List so we can access it when the Thread is done
            savedHashers.add(aHasher);
            // Instantiate a thread for the BatchPasswordHasher
            Thread aThread = new Thread(aHasher);
            // Save the Thread in a list so we can send it to the waitForThreadsToComplete() method
            theThreads.add(aThread);
            // Start the Thread so it will begin running
            aThread.start(); // Execution in this process continues - we do NOT wait for the Thread to complete (asynchronous processing)
        }

        // Now that all the Threads have been started - wait for them to complete
        waitForThreadsToComplete(theThreads);

        // So now all Threads are complete, each BatchPasswordHasher has its hashed passwords
        // Merge the hashed passwords from each BatchPasswordHasher into the final result
        for (BatchPasswordHasher aHasher : savedHashers) {
            passwordToHashes.putAll(aHasher.getPasswordToHashes()); // Copy all map entries to the result
        }

        // Return the final result
        return passwordToHashes;
    }

    /**
     * Makes the thread calling this method wait until passed in threads are done executing before proceeding.
     *
     * @param threads to wait on
     * @throws InterruptedException
     */
    public static void waitForThreadsToComplete(List<Thread> threads) throws InterruptedException {
        for (Thread thread : threads) { // Loop through the list of threads passed a parameter
            thread.join(); // Wait for the current thread to complete
        }
    }

    /**
     * Writes pairs of password and its hash to a file.
     */
    static void writePasswordsAndHashes(Map<String, String> passwordToHashes) {
        File file = new File(PASSWORDS_AND_HASHES_FILE);
        try (
            BufferedWriter writer = Files.newBufferedWriter(file.toPath());
            CSVPrinter csvPrinter = new CSVPrinter(writer, CSVFormat.DEFAULT)
        ) {
            for (Map.Entry<String, String> passwordToHash : passwordToHashes.entrySet()) {
                final String password = passwordToHash.getKey();
                final String hash = passwordToHash.getValue();

                csvPrinter.printRecord(password, hash);
            }
            System.out.println("Wrote output of batch hashing to " + file.getAbsolutePath());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
