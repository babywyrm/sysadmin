
//
//

import org.apache.ofbiz.base.crypto.HashCrypt;
import java.nio.charset.StandardCharsets;
//import org.apache.commons.codec.binary.Base64;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class Test {
    private static final String anim = "|/-\\";
    public static void main(String args[]) throws Exception {
        long i = 0;

        List < String > allLines = Files.readAllLines(Paths.get("rockyou.txt"), StandardCharsets.ISO_8859_1);
        for (String line: allLines) {
            if (HashCrypt.comparePassword("$sha$xx$xxxxxxxxxxxxxxxxxxxxxxxxx", "", line)) {
                System.out.println("Cracked: " + line);
                return;
            }

            i++;
            if (i % 1000 == 0) System.out.print("\rCracking... " + anim.charAt((int)(i / 1000) % anim.length()));
        }

        System.out.println("\r Cannot crack!");
    }
}

//
//
//
