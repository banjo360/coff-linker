use std::path::Path;
use std::collections::HashMap;
use std::io::BufRead;
use byteorder::{ReadBytesExt, LittleEndian};
use clap::Parser;

use std::fs::File;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Result;
use std::io::Read;
use std::io::BufReader;

static B_INST: u8 = 0x48;
static ADDIS_INST: u8 = 0x3C;
static LFD_INST: u8 = 0xC8;
static LFS_INST: u8 = 0xC0;

/// Patches an .OBJ file
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// File to patch
    filename: String,

    /// File containing the symbols addresses
    #[arg(short, long, default_value = "addresses.txt")]
    addresses: String,

    /// Output directory
    #[arg(short, long, default_value = "")]
    output: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut symbol_addresses = HashMap::<String, u64>::new();

    if std::fs::metadata(&args.addresses).is_ok() {
        for line in std::fs::read_to_string(&args.addresses).unwrap().lines() {
            let linedata: Vec<_> = line.split(" ").collect();
            assert_eq!(linedata.len(), 2);
            
            let addr = u64::from_str_radix(&linedata[0][2..], 16).unwrap();
            let name = linedata[1].to_string();

            symbol_addresses.insert(name, addr);
        }
    } else {
        println!("can't find '{}'", args.addresses);
    }

    let mut f = File::open(&args.filename)?;
    let format = f.read_u16::<LittleEndian>()?;
    assert_eq!(format, 0x01f2);
    let sections_count = f.read_u16::<LittleEndian>()?;
    let _timestamp = f.read_u32::<LittleEndian>()?;
    let symbols_table = f.read_u32::<LittleEndian>()?;
    let symbols_count = f.read_u32::<LittleEndian>()?;
    let strings_table = symbols_table + 18 * symbols_count;
    let _size_of_op_header = f.read_u16::<LittleEndian>()?;
    let characteristics = f.read_u16::<LittleEndian>()?;
    assert_eq!(characteristics, 0x0180);

    let mut symbols: Vec<String> = vec![String::new(); symbols_count as usize];
    let mut text_symbols = HashMap::<u16, String>::new();

    let pos = f.stream_position()?;
    f.seek(SeekFrom::Start(symbols_table as u64))?;
    let mut id = 0u32;
    while id < symbols_count {
        let mut buff = vec![0; 8usize];
        f.read(&mut buff).unwrap();

        let name = if buff[0] == 0 {
            let ptr: [u8; 4] = [ buff[4], buff[5], buff[6], buff[7] ];
            let val = u32::from_le_bytes(ptr);

            let mut data = Vec::new();
            let pos = f.stream_position()?;
            f.seek(SeekFrom::Start((strings_table + val) as u64))?;
            let mut bufread = BufReader::new(&f);
            bufread.read_until(b'\0', &mut data).unwrap();
            f.seek(SeekFrom::Start(pos))?;

            String::from_utf8(data).unwrap().trim_matches(char::from(0)).to_string()
        } else {
            String::from_utf8(buff).unwrap().trim_matches(char::from(0)).to_string()
        };
        symbols[id as usize] = name.clone();

        let _value = f.read_u32::<LittleEndian>()?;
        let section_number  = f.read_u16::<LittleEndian>()?;
        let _type_ = f.read_u16::<LittleEndian>()?;
        let _storage_class = f.read_u8()?;
        let number_of_aux_symbols = f.read_u8()?;

        if name == ".text" {
            text_symbols.insert(section_number, "".to_string());
        } else if text_symbols.contains_key(&section_number) && text_symbols[&section_number].len() == 0 {
            text_symbols.insert(section_number, name);
        }

        let mut aux = vec![0; (number_of_aux_symbols * 18) as usize];
        f.read(&mut aux).unwrap();

        id += 1u32 + (number_of_aux_symbols as u32);
    }
    f.seek(SeekFrom::Start(pos))?;

    let path = Path::new(&args.filename);
    let path = path.file_stem().unwrap();
    let path = path.to_str().unwrap();

    f.seek(SeekFrom::Start(pos))?;
    for section_id in 1..=sections_count {
        let mut buff = vec![0; 8usize];
        f.read(&mut buff).unwrap();
        let name = String::from_utf8(buff).unwrap().trim_matches(char::from(0)).to_string();
        let _size_mem = f.read_u32::<LittleEndian>()?;
        let _virt_addr = f.read_u32::<LittleEndian>()?;
        let size_raw = f.read_u32::<LittleEndian>()?;
        let raw_data = f.read_u32::<LittleEndian>()?;
        let reloc_ptr = f.read_u32::<LittleEndian>()?;
        let _lines_ptr = f.read_u32::<LittleEndian>()?;
        let reloc_count = f.read_u16::<LittleEndian>()?;
        let _lines_count = f.read_u16::<LittleEndian>()?;
        let _characs = f.read_u32::<LittleEndian>()?;

        if name == ".text" {
            let pos = f.stream_position()?;
            let self_name = &text_symbols[&section_id];

            f.seek(SeekFrom::Start(raw_data as u64))?;
            let mut buff = vec![0; size_raw as usize];
            f.read(&mut buff).unwrap();
            if reloc_count > 0 {
                f.seek(SeekFrom::Start(reloc_ptr as u64))?;
                for _ in 0..reloc_count {
                    let offset = f.read_u32::<LittleEndian>()?;
                    let symtab_index = f.read_u32::<LittleEndian>()?;
                    let type_ = f.read_u16::<LittleEndian>()?;

                    if type_ == 18 {
                        // skip IMAGE_REL_PPC_PAIR
                        continue;
                    }

                    let sym_name = &symbols[symtab_index as usize];
                    let patched = if symbol_addresses.contains_key(sym_name) {
                        symbol_addresses[sym_name] as u32
                    } else {
                        panic!("symbol '{}' not found.", sym_name);
                    };

                    let instruction = buff[offset as usize] & 0b11111100;

                    if instruction == B_INST {
                        assert_eq!(type_, 0x0006);

                        let curr_addr = symbol_addresses[self_name] as u32 + offset;
                        let addr_diff = ((patched as i64) - (curr_addr as i64)) / 4;
     
                        buff[offset as usize]       = (buff[offset as usize] & 0b11111100) | ((addr_diff >> 22) & 0b11) as u8;
                        buff[(offset + 1) as usize] = ((addr_diff >> 14) & 0xff) as u8;
                        buff[(offset + 2) as usize] = ((addr_diff >> 6) & 0xff) as u8;
                        buff[(offset + 3) as usize] = (buff[(offset + 3) as usize] & 0b11) | ((addr_diff << 2) & 0b11111100) as u8;
                    } else if instruction == ADDIS_INST {
                        assert_eq!(type_, 0x0010);
                        buff[(offset + 2) as usize] = (patched >> 24) as u8;
                        buff[(offset + 3) as usize] = ((patched >> 16) & 0xff) as u8;
                    } else if instruction == LFD_INST {
                        println!("LFD: {:?} at offset 0x{:x}", type_, offset);
                        println!("patched: 0x{:x}", patched);
                        assert_eq!(type_, 0x0011);
                    } else if instruction == LFS_INST {
                        assert_eq!(type_, 0x0011);
                        buff[(offset + 2) as usize] = ((patched >> 8) & 0xff) as u8;
                        buff[(offset + 3) as usize] = (patched & 0xff) as u8;
                    } else {
                        panic!("Unknown instruction 0x{:x} ({})", instruction, instruction >> 2);
                    }
                }
            }

            let output = if args.output.len() > 0 {
                std::fs::create_dir_all(&args.output).unwrap();
                format!("{}/", args.output)
            } else { "".to_string() };
            std::fs::write(format!("{}{}.bin", output, self_name), buff)?;
            f.seek(SeekFrom::Start(pos))?;
        } else if name == ".data" {
            let pos = f.stream_position()?;

            f.seek(SeekFrom::Start(raw_data as u64))?;
            let mut buff = vec![0; size_raw as usize];
            f.read(&mut buff).unwrap();
            if reloc_count > 0 {
                f.seek(SeekFrom::Start(reloc_ptr as u64))?;
                for _ in 0..reloc_count {
                    let offset = f.read_u32::<LittleEndian>()?;
                    let symtab_index = f.read_u32::<LittleEndian>()?;
                    let type_ = f.read_u16::<LittleEndian>()?;
                    assert_eq!(type_, 0x0002);

                    let sym_name = &symbols[symtab_index as usize];
                    let patched = if symbol_addresses.contains_key(sym_name) {
                        symbol_addresses[sym_name] as u32
                    } else {
                        panic!("symbol '{}' not found.", sym_name);
                    };
 
                    buff[offset as usize]       = (patched >> 24) as u8;
                    buff[(offset + 1) as usize] = (patched >> 16) as u8;
                    buff[(offset + 2) as usize] = (patched >> 8)  as u8;
                    buff[(offset + 3) as usize] = patched         as u8;
                }
            }

            let output = if args.output.len() > 0 {
                std::fs::create_dir_all(&args.output).unwrap();
                format!("{}/", args.output)
            } else { "".to_string() };
            std::fs::write(format!("{}{}.bin", output, path), buff)?;
            f.seek(SeekFrom::Start(pos))?;
        } else if name == ".rdata" {
            // skip
        } else {
            //println!("segment {}: {:?}", section_id, name);
        }
    }

    Ok(())
}
