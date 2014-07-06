package net.md_5.verto;

import com.google.common.base.Preconditions;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import lombok.Data;

@Data
public class ELF
{

    // Some MIPS32 ELF constants
    private static final int E_MIPS_ABI_O32 = 0x00001000;
    private static final int EF_MIPS_ARCH_32 = 0x50000000;

    //
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
        private final ByteBuf data;

        protected static ProgramHeader load(ByteBuf buf)
        {
            long p_type = buf.readUnsignedInt();
            long p_offset = buf.readUnsignedInt();
            long p_vaddr = buf.readUnsignedInt();
            long p_paddr = buf.readUnsignedInt();
            long p_filesz = buf.readUnsignedInt();
            long p_memsz = buf.readUnsignedInt();
            long p_flags = buf.readUnsignedInt();
            long p_align = buf.readUnsignedInt();

            Preconditions.checkArgument( p_memsz >= p_filesz, "MemSz cannot be smaller than filesz" );

            ByteBuf data = null;
            // This indicates a load data section
            if ( p_type == PT_LOAD )
            {
                // FIXME: Netty only supports ints!
                data = buf.alloc().directBuffer( (int) p_memsz );
                data.writeBytes( buf, (int) p_offset, (int) p_filesz );
                data.writerIndex( (int) ( data.writerIndex() + ( p_memsz - p_filesz ) ) );
            }

            return new ProgramHeader( p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align, data );
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
        private ByteBuf data;
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
            return load( Unpooled.wrappedBuffer( in.getChannel().map( FileChannel.MapMode.READ_ONLY, 0, in.length() ) ) );
        }
    }

    public static ELF load(ByteBuf buf)
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

        // e_type: 1, 2, 3, 4: relocatable, executable, shared, core
        int type = buf.readUnsignedShort();
        Preconditions.checkArgument( type == 2, "Can only handle executable ELFs (expected 2 but got %s)", type );

        // e_machine: See Wikipedia for individual values
        int machine = buf.readUnsignedShort();
        Preconditions.checkArgument( machine == 8, "Can only handle MIPS ELFs (expected 8 but got %s)", machine );

        // e_version: Another version field, bigger this time
        long longVersion = buf.readUnsignedInt();
        Preconditions.checkArgument( longVersion == 1, "Can only handle version 1 ELFs (expected 1 but got %s)", longVersion );

        // e_entry: Program entry point (long in 64 bit)
        long entry = buf.readUnsignedInt();

        // e_phoff: Program header offset
        long phOff = buf.readUnsignedInt();

        // e_shoff: Section header offset
        long shOff = buf.readUnsignedInt();

        // e_flags: Flags specific to the target arch
        long flags = buf.readUnsignedInt();
        Preconditions.checkArgument( ( flags & E_MIPS_ABI_O32 ) != 0, "Can only read O32 MIPS ELFs" );
        Preconditions.checkArgument( ( flags & EF_MIPS_ARCH_32 ) != 0, "Can only read MIPS32 ELFs" );

        // e_ehsize: Header size, should be 52 for 32 bit ELFs
        int headerSize = buf.readUnsignedShort();
        Preconditions.checkArgument( headerSize == 52, "Strange ELF header size (expected 52 but got %s)", headerSize );

        // e_phentsize: Size of a program header entry, should be 32 for 32 bit ELFs
        int phEntSize = buf.readUnsignedShort();
        Preconditions.checkArgument( phEntSize == 32, "Strange program header size (expected 32 but got %s)", phEntSize );

        // e_phnum: Number of program header entries
        int phNum = buf.readUnsignedShort();
        Preconditions.checkArgument( phNum != 0xFFFF, "Program headers not in expected place (phNum was 0xFFFF)" );

        // e_shentsize: Size of a section header entry, should be 40 for 32 bit ELFs
        int shEntSize = buf.readUnsignedShort();
        Preconditions.checkArgument( shEntSize == 40, "Strange section header size (expected 40 but got %s)", shEntSize );

        // e_shnum: Number of section header entries
        int shNum = buf.readUnsignedShort();
        Preconditions.checkArgument( shNum != 0, "Section headers not in expected place (shNum was 0)" );

        // e_shstrndx: Index of section header table entry that contains section names
        int shNameOff = buf.readUnsignedShort();
        Preconditions.checkArgument( shNameOff != 0, "Program must have a section header name table (shNameOff was 0)" );
        Preconditions.checkArgument( shNameOff != 0xFFFF, "Section name table not in expected place (shNameOff was 0xFFFF)" );

        Preconditions.checkState( buf.readerIndex() == phOff, "Not at start of program header table (expected position %s but was %s)", phOff, buf.readerIndex() );

        ProgramHeader[] programHeaders = new ProgramHeader[ phNum ];
        for ( int i = 0; i < programHeaders.length; i++ )
        {
            // Check we are starting from the right place
            long expectedStart = phOff + ( i * phEntSize );
            Preconditions.checkState( buf.readerIndex() == expectedStart, "Not at correct start in program header table (expected position %s but was %s)", expectedStart );

            // Load section
            programHeaders[i] = ProgramHeader.load( buf );

            // Check we are ending in the right place
            long expectedEnd = expectedStart + phEntSize;
            Preconditions.checkState( buf.readerIndex() == expectedEnd, "Not at correct end in program header table (expected position %s but was %s)", expectedEnd );
        }

        // Skip to start of section headers
        buf.readerIndex( (int) shOff ); // FIXME: Int cast
        SectionHeader[] sectionHeaders = new SectionHeader[ shNum ];
        for ( int i = 0; i < sectionHeaders.length; i++ )
        {
            // Check we are starting from the right place
            long expectedStart = shOff + ( i * shEntSize );
            Preconditions.checkState( buf.readerIndex() == expectedStart, "Not at correct start in program header table (expected position %s but was %s)", expectedStart );

            // Load section
            sectionHeaders[i] = new SectionHeader( buf );

            // Check we are ending in the right place
            long expectedEnd = expectedStart + shEntSize;
            Preconditions.checkState( buf.readerIndex() == expectedEnd, "Not at correct end in program header table (expected position %s but was %s)", expectedEnd );
        }

        SectionHeader stringTable = sectionHeaders[shNameOff];
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
            System.out.println( header );
        }

        return null;
    }
}
