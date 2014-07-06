package net.md_5.verto;

import com.google.gson.GsonBuilder;
import java.io.File;

public class Verto
{

    public static void main(String[] args) throws Exception
    {
        ELF elf = ELF.load( new File( "examples/hello" ) );
        System.out.println( "Read elf file:" );
        System.out.println( new GsonBuilder().setPrettyPrinting().create().toJson( elf ) );
    }
}
