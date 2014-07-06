package net.md_5.verto;

import com.google.common.base.Preconditions;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import lombok.Data;

/**
 * This is a small ELF parser designed specifically for MIPS32 ELF files. In
 * order to prevent surprises in the development of Verto, there is an extremely
 * large amount of validation to ensure that only pristine ELF files get past
 * the loading stage.
 *
 * Anyone looking to contribute further to this file should attempt to factor
 * out all of the magic ELF constants (man 5 elf) and validate them accordingly.
 */
@Data
public class ELF
{

    // Some MIPS32 ELF constants
    private static final int E_MIPS_ABI_O32 = 0x00001000;
    private static final int EF_MIPS_ARCH_32 = 0x50000000;
    //
    private final int e_type;
    private final int e_machine;
    private final long e_version;
    private final long e_entry;
    private final long e_phoff;
    private final long e_shoff;
    private final long e_flags;
    private final int e_ehsize;
    private final int e_phentsize;
    private final int e_phnum;
    private final int e_shentsize;
    private final int e_shnum;
    private final int e_shstrndx;
    //
    private final ProgramHeader[] programHeaders;
    private final SectionHeader[] sectionHeaders;

    public ELF(ByteBuf buf)
    {
        if ( buf.readUnsignedByte() != 0x7F || buf.readUnsignedByte() != 'E' || buf.readUnsignedByte() != 'L' || buf.readUnsignedByte() != 'F' )
        {
            throw new IllegalArgumentException( "Not an ELF file (Invalid Magic)" );
        }

        // EI_CLASS: 1 for 32 bit, 2 for 64 bit
        short clazz = buf.readUnsignedByte();
        Preconditions.checkArgument( clazz == 1, "Can only handle 32 bit ELFs (expected 1 but got %s)", clazz );

        // EL_DATA: 1 for little endian, 2 for big endian
        short endian = buf.readUnsignedByte();
        Preconditions.checkArgument( endian == 2, "Can only handle big endian ELFs (expected 2 but got %s)", endian );

        // EL_VERSION: 1 for original ELF version
        short version = buf.readUnsignedByte();
        Preconditions.checkArgument( version == 1, "Can only handle version 1 ELFs (expected 1 but got %s)" );

        // EI_OSABI: Operating system ABI, check Wikipedia for individual values
        short abi = buf.readUnsignedByte();
        Preconditions.checkArgument( abi == 0, "Can only handle System V ELFs (expected 0 but got %s)", abi );

        // EI_ABIVERSION
        short abiVer = buf.readUnsignedByte();
        Preconditions.checkArgument( abiVer == 0, "Can only handle version 0 ABI (expected 0 but got %s)", abiVer );

        // EI_PAD: 7 bytes padding
        buf.skipBytes( 7 );

        /**
         * The actual ELF parsing starts here, the above is just the header
         */
        // e_type: 1, 2, 3, 4: relocatable, executable, shared, core
        e_type = buf.readUnsignedShort();
        Preconditions.checkArgument( e_type == 2, "Can only handle executable ELFs (expected 2 but got %s)", e_type );

        // e_machine: See Wikipedia for individual values
        e_machine = buf.readUnsignedShort();
        Preconditions.checkArgument( e_machine == 8, "Can only handle MIPS ELFs (expected 8 but got %s)", e_machine );

        // e_version: Another version field, bigger this time
        e_version = buf.readUnsignedInt();
        Preconditions.checkArgument( e_version == 1, "Can only handle version 1 ELFs (expected 1 but got %s)", e_version );

        // e_entry: Program entry point (long in 64 bit)
        e_entry = buf.readUnsignedInt();

        // e_phoff: Program header offset
        e_phoff = buf.readUnsignedInt();

        // e_shoff: Section header offset
        e_shoff = buf.readUnsignedInt();

        // e_flags: Flags specific to the target arch
        e_flags = buf.readUnsignedInt();
        Preconditions.checkArgument( ( e_flags & E_MIPS_ABI_O32 ) != 0, "Can only read O32 MIPS ELFs" );
        Preconditions.checkArgument( ( e_flags & EF_MIPS_ARCH_32 ) != 0, "Can only read MIPS32 ELFs" );

        // e_ehsize: Header size, should be 52 for 32 bit ELFs
        e_ehsize = buf.readUnsignedShort();
        Preconditions.checkArgument( e_ehsize == 52, "Strange ELF header size (expected 52 but got %s)", e_ehsize );

        // e_phentsize: Size of a program header entry, should be 32 for 32 bit ELFs
        e_phentsize = buf.readUnsignedShort();
        Preconditions.checkArgument( e_phentsize == 32, "Strange program header size (expected 32 but got %s)", e_phentsize );

        // e_phnum: Number of program header entries
        e_phnum = buf.readUnsignedShort();
        Preconditions.checkArgument( e_phnum != 0xFFFF, "Program headers not in expected place (phNum was 0xFFFF)" );

        // e_shentsize: Size of a section header entry, should be 40 for 32 bit ELFs
        e_shentsize = buf.readUnsignedShort();
        Preconditions.checkArgument( e_shentsize == 40, "Strange section header size (expected 40 but got %s)", e_shentsize );

        // e_shnum: Number of section header entries
        e_shnum = buf.readUnsignedShort();
        Preconditions.checkArgument( e_shnum != 0, "Section headers not in expected place (shNum was 0)" );

        // e_shstrndx: Index of section header table entry that contains section names
        e_shstrndx = buf.readUnsignedShort();
        Preconditions.checkArgument( e_shstrndx != 0, "Program must have a section header name table (shNameOff was 0)" );
        Preconditions.checkArgument( e_shstrndx != 0xFFFF, "Section name table not in expected place (shNameOff was 0xFFFF)" );

        Preconditions.checkState( buf.readerIndex() == e_phoff, "Not at start of program header table (expected position %s but was %s)", e_phoff, buf.readerIndex() );

        programHeaders = new ProgramHeader[ e_phnum ];
        for ( int i = 0; i < programHeaders.length; i++ )
        {
            // Check we are starting from the right place
            long expectedStart = e_phoff + ( i * e_phentsize );
            Preconditions.checkState( buf.readerIndex() == expectedStart, "Not at correct start in program header table (expected position %s but was %s)", expectedStart );

            // Load section
            programHeaders[i] = new ProgramHeader( buf );

            // Check we are ending in the right place
            long expectedEnd = expectedStart + e_phentsize;
            Preconditions.checkState( buf.readerIndex() == expectedEnd, "Not at correct end in program header table (expected position %s but was %s)", expectedEnd );
        }

        // Skip to start of section headers
        buf.readerIndex( (int) e_shoff ); // FIXME: Int cast
        sectionHeaders = new SectionHeader[ e_shnum ];
        for ( int i = 0; i < sectionHeaders.length; i++ )
        {
            // Check we are starting from the right place
            long expectedStart = e_shoff + ( i * e_shentsize );
            Preconditions.checkState( buf.readerIndex() == expectedStart, "Not at correct start in program header table (expected position %s but was %s)", expectedStart );

            // Load section
            sectionHeaders[i] = new SectionHeader( buf );

            // Check we are ending in the right place
            long expectedEnd = expectedStart + e_shentsize;
            Preconditions.checkState( buf.readerIndex() == expectedEnd, "Not at correct end in program header table (expected position %s but was %s)", expectedEnd );
        }

        SectionHeader stringTable = sectionHeaders[e_shstrndx];
        for ( SectionHeader header : sectionHeaders )
        {
            StringBuilder name = new StringBuilder();

            long offset = header.getSh_name();
            while ( true )
            {
                byte b = stringTable.getData().getByte( (int) offset++ );
                if ( b == 0 )
                {
                    break;
                }
                name.append( (char) b );
            }

            header.setName( name.toString() );
        }
    }

    @Data
    public static class ProgramHeader
    {

        private static final int PT_LOAD = 1;
        //
        private final long p_type;
        private final long p_offset;
        private final long p_vaddr;
        private final long p_paddr;
        private final long p_filesz;
        private final long p_memsz;
        private final long p_flags;
        private final long p_align;
        //
        private transient ByteBuf data;

        protected ProgramHeader(ByteBuf buf)
        {
            p_type = buf.readUnsignedInt();
            p_offset = buf.readUnsignedInt();
            p_vaddr = buf.readUnsignedInt();
            p_paddr = buf.readUnsignedInt();
            p_filesz = buf.readUnsignedInt();
            p_memsz = buf.readUnsignedInt();
            p_flags = buf.readUnsignedInt();
            p_align = buf.readUnsignedInt();

            Preconditions.checkArgument( p_memsz >= p_filesz, "MemSz cannot be smaller than filesz" );

            // This indicates a load data section
            if ( p_type == PT_LOAD )
            {
                // FIXME: Netty only supports ints!
                data = buf.alloc().directBuffer( (int) p_memsz );
                data.writeBytes( buf, (int) p_offset, (int) p_filesz );
                data.writerIndex( (int) ( data.writerIndex() + ( p_memsz - p_filesz ) ) );
            }
        }
    }

    @Data
    public static class SectionHeader
    {

        private static final int SHT_NULL = 0;
        //
        private final long sh_name;
        private final long sh_type;
        private final long sh_flags;
        private final long sh_addr;
        private final long sh_offset;
        private final long sh_size;
        private final long sh_link;
        private final long sh_info;
        private final long sh_addralign;
        private final long sh_entsize;
        //
        private transient ByteBuf data;
        private String name;

        public SectionHeader(ByteBuf buf)
        {
            this.sh_name = buf.readUnsignedInt();
            this.sh_type = buf.readUnsignedInt();
            this.sh_flags = buf.readUnsignedInt();
            this.sh_addr = buf.readUnsignedInt();
            this.sh_offset = buf.readUnsignedInt();
            this.sh_size = buf.readUnsignedInt();
            this.sh_link = buf.readUnsignedInt();
            this.sh_info = buf.readUnsignedInt();
            this.sh_addralign = buf.readUnsignedInt();
            this.sh_entsize = buf.readUnsignedInt();

            if ( sh_type == SHT_NULL )
            {
                Preconditions.checkState( sh_addr == 0 && sh_offset == 0 && sh_size == 0, "Section header has type SHT_NULL but appears to have data" );
            } else
            {
                // FIXME: Netty only supports ints!
                // TODO: SH_NODATA should be initialized to 0?
                data = buf.alloc().directBuffer( (int) sh_size );
                data.writeBytes( buf, (int) sh_offset, (int) sh_size );
            }
        }
    }

    public static ELF load(File file) throws IOException
    {
        try ( RandomAccessFile in = new RandomAccessFile( file, "r" ) )
        {
            return new ELF( Unpooled.wrappedBuffer( in.getChannel().map( FileChannel.MapMode.READ_ONLY, 0, in.length() ) ) );
        }
    }
}
