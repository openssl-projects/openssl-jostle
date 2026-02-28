package org.openssl.jostle;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.File;

public class LoaderUtilsTest
{
    @Test()
    public void testMakeFile_1() throws Exception {

        File testPath = File.createTempFile("test", ".txt");
        testPath.deleteOnExit();
        try
        {
            LoaderUtils.makeFile(testPath, "../test");
            Assertions.fail();
        } catch (IllegalStateException e) {
            Assertions.assertTrue(e.getMessage().contains("is outside of prefix"));
        }

    }

    @Test()
    public void testMakeFile_2() throws Exception {

        File testPath = File.createTempFile("test", ".txt");
        testPath.deleteOnExit();
        try
        {
            LoaderUtils.makeFile(testPath.getAbsolutePath(), "../test");
            Assertions.fail();
        } catch (IllegalStateException e) {
            Assertions.assertTrue(e.getMessage().contains("is outside of prefix"));
        }

    }

    @Test()
    public void testMakeFile_3() throws Exception {

        File testPath = File.createTempFile("test", ".txt");
        testPath.deleteOnExit();
        try
        {
            LoaderUtils.makeFile(testPath.getAbsolutePath(), "..///..///test");
            Assertions.fail();
        } catch (IllegalStateException e) {
            Assertions.assertTrue(e.getMessage().contains("is outside of prefix"));
        }

    }

    @Test()
    public void testCompareStream_1() throws Exception
    {
        ByteArrayInputStream left = new ByteArrayInputStream("test".getBytes());
        ByteArrayInputStream right = new ByteArrayInputStream("test".getBytes());

        Assertions.assertTrue(LoaderUtils.isContentSame(left, right));
    }

    @Test()
    public void testCompareStream_2() throws Exception
    {
        ByteArrayInputStream left = new ByteArrayInputStream("tes".getBytes());
        ByteArrayInputStream right = new ByteArrayInputStream("test".getBytes());

        Assertions.assertFalse(LoaderUtils.isContentSame(left, right));
    }

    @Test()
    public void testCompareStream_3() throws Exception
    {
        ByteArrayInputStream left = new ByteArrayInputStream("test".getBytes());
        ByteArrayInputStream right = new ByteArrayInputStream("tes".getBytes());

        Assertions.assertFalse(LoaderUtils.isContentSame(left, right));
    }

    @Test()
    public void testCompareStream_4() throws Exception
    {
        ByteArrayInputStream left = new ByteArrayInputStream(new byte[0]);
        ByteArrayInputStream right = new ByteArrayInputStream("test".getBytes());

        Assertions.assertFalse(LoaderUtils.isContentSame(left, right));
    }

    @Test()
    public void testCompareStream_5() throws Exception
    {
        ByteArrayInputStream left = new ByteArrayInputStream("test".getBytes());
        ByteArrayInputStream right = new ByteArrayInputStream(new byte[0]);

        Assertions.assertFalse(LoaderUtils.isContentSame(left, right));
    }

    @Test()
    public void testCompareStream_6() throws Exception
    {
        ByteArrayInputStream left = new ByteArrayInputStream(new byte[0]);
        ByteArrayInputStream right = new ByteArrayInputStream(new byte[0]);

        Assertions.assertTrue(LoaderUtils.isContentSame(left, right));
    }

    @Test()
    public void testCompareStream_7() throws Exception
    {
        ByteArrayInputStream left = new ByteArrayInputStream("est".getBytes());
        ByteArrayInputStream right = new ByteArrayInputStream("test".getBytes());

        Assertions.assertFalse(LoaderUtils.isContentSame(left, right));
    }

}
