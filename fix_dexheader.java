import java.util.zip.Adler32;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class fix_dexheader {
    public static void main(String[] args){
        try{
            String filename = "./classes.dex";//original dex file
            File unShellApkFile = new File(filename);
            byte[] unShellDexArray=readFileBytes(unShellApkFile);
            
            fixFileSizeHeader(unShellDexArray);
            fixSHA1Header(unShellDexArray);
            fixCheckSumHeader(unShellDexArray);

            String str = "./fix.dex";//name of fixed dex
            File file = new File(str);
            if (file.createNewFile()) {
                FileOutputStream localFileOutputStream = new FileOutputStream(str);
                localFileOutputStream.write(unShellDexArray);
                localFileOutputStream.flush();
                localFileOutputStream.close();
            } else {
                System.out.println("New dex file created failed");
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void fixCheckSumHeader(byte[] dexBytes) {
        Adler32 adler = new Adler32();
        adler.update(dexBytes, 12, dexBytes.length - 12);
        long value = adler.getValue();
        int va = (int) value;
        byte[] newcs = intToByte(va);
        byte[] recs = new byte[4];
        for (int i = 0; i < 4; i++) {
            recs[i] = newcs[newcs.length - 1 - i];
            System.out.println(Integer.toHexString(newcs[i]));
        }
        System.arraycopy(recs, 0, dexBytes, 8, 4);
        System.out.println(Long.toHexString(value));
        System.out.println();
    }

    private static void fixSHA1Header(byte[] dexBytes) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(dexBytes, 32, dexBytes.length - 32);
        byte[] newdt = md.digest();
        System.arraycopy(newdt, 0, dexBytes, 12, 20);
        StringBuilder hexstr = new StringBuilder();
        for (byte b : newdt) {
            hexstr.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        }
        System.out.println(hexstr);
    }

    private static void fixFileSizeHeader(byte[] dexBytes) {
        byte[] newfs = intToByte(dexBytes.length);
        System.out.println(Integer.toHexString(dexBytes.length));
        byte[] refs = new byte[4];
        for (int i = 0; i < 4; i++) {
            refs[i] = newfs[newfs.length - 1 - i];
            System.out.println(Integer.toHexString(newfs[i]));
        }
        System.arraycopy(refs, 0, dexBytes, 32, 4);
    }

    public static byte[] intToByte(int number) {
        byte[] b = new byte[4];
        for (int i = 3; i >= 0; i--) {
            b[i] = (byte) (number % 256);
            number >>= 8;
        }
        return b;
    }

    private static byte[] readFileBytes(File file) throws IOException {
        byte[] arrayOfByte = new byte[1024];
        ByteArrayOutputStream localByteArrayOutputStream = new ByteArrayOutputStream();
        FileInputStream fis = new FileInputStream(file);
        while (true) {
            int i = fis.read(arrayOfByte);
            if (i != -1) {
                localByteArrayOutputStream.write(arrayOfByte, 0, i);
            } else {
                return localByteArrayOutputStream.toByteArray();
            }
        }
    }

}
