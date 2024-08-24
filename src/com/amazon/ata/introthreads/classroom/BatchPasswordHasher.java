package com.amazon.ata.introthreads.classroom;

import com.google.common.collect.Maps;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A class to hash a batch of passwords in a separate thread.
 */
// This class needs to be modified to be able to run concurrent
    // 1. Be sure the class is immutable
    //  a. Make class final
    //  b. Make instance variables final (already final in this class)
    //  c. Check the constructors for reference parameters - make sure they're defensive copied (not simply assigned)
    //  d. Check any instance variables returned - make sure they're returned by reference
    //  e. No setters
    // 2. Make it Runnable or a sublcass Thread
    // We are implementing Runnable instead of implementing Thread in case this needs to be a subclass someday

public final class BatchPasswordHasher implements Runnable {

    private final List<String> passwords;
    private final Map<String, String> passwordToHashes;
    private final String salt;

    // Constructor receives a reference to a List - defensive copy to instance variable
    public BatchPasswordHasher(List<String> passwords, String salt) {
        //this.passwords = passwords; // Replace with defensive copy
        this.passwords = new ArrayList<>(passwords);
        this.salt = salt;
        passwordToHashes = new HashMap<>();
    }

    /**
     *  Hashes all of the passwords, and stores the hashes in the passwordToHashes Map.
     */
    public void hashPasswords() {
        try {
            for (String password : passwords) {
                final String hash = PasswordUtil.hash(password, salt);
                passwordToHashes.put(password, hash);
            }
            System.out.println(String.format("Completed hashing batch of %d passwords.", passwords.size()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Returns a map where the key is a plain text password and the key is the hashed version of the plaintext password
     * and the class' salt value.
     *
     * @return passwordToHashes - a map of passwords to their hash value.
     */
    // Since we're returning a reference to an instance variable
    // we should defensive return it
    public Map<String, String> getPasswordToHashes() {
        Map<String, String> newMap = new HashMap<>(); // Instantiate a map to return
        newMap.putAll(passwordToHashes); // Copy all entries from the instance Map
        return newMap; // Return the copy of the Map
        //return passwordToHashes;
    }

    // This method was required by the Runnable interface
    // The run() method is what is run when this process is on a Thread
    // like main() in a Java app or handleRequest() in an AWS Lambda function
    @Override
    public void run() {
        this.hashPasswords(); // Call our hashPasswords() to hash the passwords
        // this. is optional since we're in the same class
    }
}
