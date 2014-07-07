package net.md_5.verto;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
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
            // System.out.println( gson.toJson( elf ) );
            System.out.println( "===============================================================================" );
        }

        ELF elf = ELF.load( new File( "examples/return.stripped" ) );
        System.out.println( gson.toJson( elf ) );

        ByteBuf processImage = Unpooled.directBuffer();
        for ( ELF.ProgramHeader programHeader : elf.getProgramHeaders() )
        {
            if ( programHeader.getData() != null )
            {
                int requiredCapacity = (int) ( programHeader.getP_vaddr() + programHeader.getP_memsz() );
                if ( requiredCapacity > processImage.capacity() )
                {
                    processImage.capacity( requiredCapacity );
                    processImage.writerIndex( processImage.capacity() );
                }

                programHeader.getData().readBytes( processImage, (int) programHeader.getP_vaddr(), (int) programHeader.getP_memsz() );
            }
        }

        for ( ELF.SectionHeader sectionHeader : elf.getSectionHeaders() )
        {
            if ( sectionHeader.getSh_addr() != 0 )
            {
                int requiredCapacity = (int) ( sectionHeader.getSh_addr() + sectionHeader.getSh_size() );
                if ( requiredCapacity > processImage.capacity() )
                {
                    processImage.capacity( requiredCapacity );
                    processImage.writerIndex( processImage.capacity() );
                }

                sectionHeader.getData().readBytes( processImage, (int) sectionHeader.getSh_addr(), (int) sectionHeader.getSh_size() );
            }
        }

        System.out.println( "Produced ELF image of size: " + processImage.capacity() );

        processImage.readerIndex( (int) elf.getE_entry() );
        System.out.println( "Entry: " + Long.toHexString( elf.getE_entry() ) );
        System.out.println( "First Instruction: " + Long.toHexString( processImage.readInt() ) );
    }
}
