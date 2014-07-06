package net.md_5.verto;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.File;

public class Verto
{

    public static void main(String[] args) throws Exception
    {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        for ( String file : new String[]
        {
            "examples/return.stripped", "examples/return", "examples/hello.stripped", "examples/hello"
        } )
        {
            ELF elf = ELF.load( new File( file ) );
            System.out.println( gson.toJson( elf ) );
            System.out.println( "===============================================================================" );
        }
    }
}
