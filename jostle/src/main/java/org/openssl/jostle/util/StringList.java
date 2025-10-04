/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.util;

/**
 * An interface defining a list of strings.
 */
public interface StringList
    extends Iterable<String>
{
    /**
     * Add a String to the list.
     *
     * @param s the String to add.
     * @return true
     */
    boolean add(String s);

    /**
     * Get the string at index index.
     *
     * @param index the index position of the String of interest.
     * @return the String at position index.
     */
    String get(int index);

    int size();

    /**
     * Return the contents of the list as an array.
     *
     * @return an array of String.
     */
    String[] toStringArray();

    /**
     * Return a section of the contents of the list. If the list is too short the array is filled with nulls.
     *
     * @param from the initial index of the range to be copied, inclusive
     * @param to the final index of the range to be copied, exclusive.
     * @return an array of length to - from
     */
    String[] toStringArray(int from, int to);
}
