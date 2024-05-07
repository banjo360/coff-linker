use std::io::Write;
use std::fs;
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

static ADDI_INST: u8 = 0x38;
static ADDIS_INST: u8 = 0x3C;
static B_INST: u8 = 0x48;
static LFD_INST: u8 = 0xC8;
static LFS_INST: u8 = 0xC0;
static LWZ_INST: u8 = 0x80;
static STW_INST: u8 = 0x90;

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
        panic!("can't find '{}'", args.addresses);
    }

    let mut f = File::open(&args.filename)?;
    let format = f.read_u16::<LittleEndian>()?;
    assert_eq!(format, 0x01f2);
    let sections_count = f.read_u16::<LittleEndian>()?;
    let _timestamp = f.read_u32::<LittleEndian>()?;
    let symbols_table = f.read_u32::<LittleEndian>()?;
    let symbols_count = f.read_u32::<LittleEndian>()?;
    let strings_table = symbols_table + 18 * symbols_count;
    let size_of_op_header = f.read_u16::<LittleEndian>()?;
    let characteristics = f.read_u16::<LittleEndian>()?;
    assert_eq!(characteristics, 0x0180);
    assert_eq!(size_of_op_header, 0);

    let mut symbols: Vec<String> = vec![String::new(); symbols_count as usize];
    let mut section_symbol_names = HashMap::<u16, Vec<(String, u32)>>::new();

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

        let value = f.read_u32::<LittleEndian>()?;
        let section_number  = f.read_u16::<LittleEndian>()?;
        let _type_ = f.read_u16::<LittleEndian>()?;
        let _storage_class = f.read_u8()?;
        let number_of_aux_symbols = f.read_u8()?;

        if section_symbol_names.contains_key(&section_number) {
            section_symbol_names.get_mut(&section_number).unwrap().push((name, value));
        } else {
            section_symbol_names.insert(section_number, vec![(name, value)]);
        }

        let mut aux = vec![0; (number_of_aux_symbols * 18) as usize];
        f.read(&mut aux).unwrap();

        id += 1u32 + (number_of_aux_symbols as u32);
    }

    let path = Path::new(&args.filename);
    let path = path.file_stem().unwrap();
    let path = path.to_str().unwrap();

    let output = if args.output.len() > 0 {
        std::fs::create_dir_all(&args.output).unwrap();
        format!("{}/", args.output)
    } else { "".to_string() };
    let _ = fs::remove_file(format!("{}{}.data.bin", output, path));
    let _ = fs::remove_file(format!("{}{}.rdata.bin", output, path));
    let _ = fs::remove_file(format!("{}{}.bss.bin", output, path));

    let mut extra_rdata_offset = 0;
    let mut extra_data_offset = 0;
    let data_section_end = 0x825085b0; // BK's, need to make it dynamic

    // phase 0: get .text size
    // phase 1: calculate .rdata's virtual addresses
    // phase 2: patch and export .text
    for phase in 0..3 {
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

            if name == ".text" && phase == 2 {
                let pos = f.stream_position()?;
                let self_name_vec = &section_symbol_names[&section_id];
                assert_eq!(name, self_name_vec[0].0);
                let self_name = &self_name_vec[1].0;

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
                            panic!("Unknown symbol: {sym_name}");
                        };

                        let instruction = buff[offset as usize] & 0b11111100;

                        if instruction == B_INST {
                            assert_eq!(type_, 0x0006);

                            if !symbol_addresses.contains_key(self_name) {
                                panic!("Can't find address of '{self_name}'");
                            }

                            let curr_addr = symbol_addresses[self_name] as u32 + offset;
                            let addr_diff = ((patched as i64) - (curr_addr as i64)) / 4;

                            buff[offset as usize]       = (buff[offset as usize] & 0b11111100) | ((addr_diff >> 22) & 0b11) as u8;
                            buff[(offset + 1) as usize] = ((addr_diff >> 14) & 0xff) as u8;
                            buff[(offset + 2) as usize] = ((addr_diff >> 6) & 0xff) as u8;
                            buff[(offset + 3) as usize] = (buff[(offset + 3) as usize] & 0b11) | ((addr_diff << 2) & 0b11111100) as u8;
                        } else if instruction == ADDIS_INST {
                            assert_eq!(type_, 0x0010);
                            let third_byte = if (patched & 0x8000) != 0 {
                                (((patched >> 16) + 1) & 0xff) as u8
                            } else {
                                ((patched >> 16) & 0xff) as u8
                            };
                            buff[(offset + 2) as usize] = (patched >> 24) as u8;
                            buff[(offset + 3) as usize] = third_byte;
                        } else if instruction == LFD_INST {
                            assert_eq!(type_, 0x0011);
                            buff[(offset + 2) as usize] = ((patched >> 8) & 0xff) as u8;
                            buff[(offset + 3) as usize] = (patched & 0xff) as u8;
                        } else if instruction == LFS_INST {
                            assert_eq!(type_, 0x0011);
                            buff[(offset + 2) as usize] = ((patched >> 8) & 0xff) as u8;
                            buff[(offset + 3) as usize] = (patched & 0xff) as u8;
                        } else if instruction == LWZ_INST {
                            assert_eq!(type_, 0x0011);
                            buff[(offset + 2) as usize] = ((patched >> 8) & 0xff) as u8;
                            buff[(offset + 3) as usize] = (patched & 0xff) as u8;
                        } else if instruction == STW_INST {
                            assert_eq!(type_, 0x0011);
                            buff[(offset + 2) as usize] = ((patched >> 8) & 0xff) as u8;
                            buff[(offset + 3) as usize] = (patched & 0xff) as u8;
                        } else if instruction == ADDI_INST {
                            assert_eq!(type_, 0x0011);
                            buff[(offset + 2) as usize] = ((patched >> 8) & 0xff) as u8;
                            buff[(offset + 3) as usize] = (patched & 0xff) as u8;
                        } else {
                            panic!("{sym_name}: Unknown instruction 0x{:x} ({}) at offset {:#X}", instruction, instruction >> 2, offset + raw_data);
                        }
                    }
                }

                std::fs::write(format!("{}{}.bin", output, self_name), buff)?;
                f.seek(SeekFrom::Start(pos))?;
            } else if name == ".rdata" && phase == 1 {
                let pos = f.stream_position()?;
                let self_name_vec = &section_symbol_names[&section_id];
                assert_eq!(name, self_name_vec[0].0);
                let self_name = &self_name_vec[1].0;

                // hardcoded Banjo's ".rdata end section" address
                let new_addr = 0x82079C88 + extra_rdata_offset as u64;
                symbol_addresses.insert(self_name.clone(), new_addr);
                extra_rdata_offset += size_raw;

                f.seek(SeekFrom::Start(raw_data as u64))?;
                let mut buff = vec![0; size_raw as usize];
                f.read(&mut buff).unwrap();

                assert_eq!(reloc_count, 0);
                /*if reloc_count > 0 {
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
                }*/

                let mut output_file = File::options().create(true).write(true).append(true).open(format!("{}{}{}.bin", output, path, name))?;
                output_file.write(&buff)?;
                f.seek(SeekFrom::Start(pos))?;
            } else if name == ".data" && phase == 1 {
                let pos = f.stream_position()?;
                let self_name_vec = &section_symbol_names[&section_id];
                assert_eq!(name, self_name_vec[0].0);
                let self_name = &self_name_vec[1].0;

                println!("{:?}", self_name_vec);

                // hardcoded Banjo's ".data end section" address
                let new_addr = 0x825085b0 + extra_data_offset as u64;
                symbol_addresses.insert(self_name.clone(), new_addr);
                extra_data_offset += size_raw;

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

                let mut output_file = File::options().create(true).write(true).append(true).open(format!("{}{}{}.bin", output, path, name))?;
                output_file.write(&buff)?;
                f.seek(SeekFrom::Start(pos))?;
            } else if name == ".bss" && phase == 1 {
                assert_eq!(reloc_count, 0);
                let pos = f.stream_position()?;
                let self_name_vec = &section_symbol_names[&section_id];
                assert_eq!(name, self_name_vec[0].0);

                for (self_name, offset) in self_name_vec.iter().skip(1) {
                    let new_addr = data_section_end + extra_data_offset as u64 + *offset as u64;
                    symbol_addresses.insert(self_name.clone(), new_addr);
                }

                extra_data_offset += size_raw;

                let mut output_file = File::options().create(true).write(true).append(true).open(format!("{}{}{}.bin", output, path, name))?;
                output_file.write(&vec![0u8; size_raw as usize])?;

                f.seek(SeekFrom::Start(pos))?;
            }
        }
    }

    Ok(())
}
