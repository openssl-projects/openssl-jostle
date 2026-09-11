/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.module;

import org.junit.jupiter.api.Assertions;

/**
 * The placements this source set runs under, declared by the build task and
 * read here. Declared, never detected: a check that reads what it finds and
 * calls it correct cannot fail.
 *
 * <table>
 * <tr><th>cell</th><th>jostle</th><th>bcprov</th></tr>
 * <tr><td>NAMED</td><td>module path</td><td>module path, explicit module</td></tr>
 * <tr><td>AUTOMATIC</td><td>module path</td><td>module path, automatic (UNSIGNED copy)</td></tr>
 * <tr><td>UNNAMED</td><td>module path</td><td>classpath</td></tr>
 * <tr><td>CONTROL</td><td>classpath</td><td>classpath</td></tr>
 * </table>
 *
 * <p>CONTROL is the shape the rest of the matrix runs, and is the control
 * for falsification: a deleted {@code exports} must leave it green.
 */
public enum ModuleCell
{
    NAMED, AUTOMATIC, UNNAMED, CONTROL;

    private static final String PROPERTY = "jostle.test.module.cell";

    public static ModuleCell current()
    {
        String v = System.getProperty(PROPERTY);
        Assertions.assertNotNull(v, PROPERTY + " is unset, so every placement assertion is vacuous");
        return ModuleCell.valueOf(v.toUpperCase());
    }

    /** Is jostle expected on the module path in this cell? */
    public boolean jostleIsModular()
    {
        return this != CONTROL;
    }

    /** Is bcprov expected on the module path in this cell? */
    public boolean bcprovIsModular()
    {
        return this == NAMED || this == AUTOMATIC;
    }
}
