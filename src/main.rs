#![allow(unused)]

use std::collections::HashMap;
use std::io::BufRead;
use byteorder::{ReadBytesExt, LittleEndian};

use std::fs::File;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Result;
use std::io::Read;
use std::io::BufReader;
use std::env;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        panic!("Not enough args");
    }

    // TODO: read addresses of functions from addresses.txt

    let mut f = File::open(&args[1])?;
    let format = f.read_u16::<LittleEndian>()?;
    assert_eq!(format, 0x01f2);
    let sections_count = f.read_u16::<LittleEndian>()?;
    let timestamp = f.read_u32::<LittleEndian>()?;
    let symbols_table = f.read_u32::<LittleEndian>()?;
    let symbols_count = f.read_u32::<LittleEndian>()?;
    let strings_table = (symbols_table + 18 * symbols_count);
    let _size_of_op_header = f.read_u16::<LittleEndian>()?;
    let characteristics = f.read_u16::<LittleEndian>()?;
    assert_eq!(characteristics, 0x0180);

    let mut symbols: Vec<String> = vec![String::new(); symbols_count as usize];
    let mut text_symbols = HashMap::<u16, String>::new();
    let mut data_symbols = HashMap::<u16, String>::new();

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
        let type_ = f.read_u16::<LittleEndian>()?;
        let storage_class = f.read_u8()?;
        let number_of_aux_symbols = f.read_u8()?;

        if name == ".text" {
            text_symbols.insert(section_number, "".to_string());
        } else if text_symbols.contains_key(&section_number) && name.starts_with("FUN_") {
            text_symbols.insert(section_number, name);
        } else if name == ".data" {
            data_symbols.insert(section_number, "".to_string());
        } else if data_symbols.contains_key(&section_number) && name.starts_with("DAT_") {
            data_symbols.insert(section_number, name);
        }

        let mut aux = vec![0; (number_of_aux_symbols * 18) as usize];
        f.read(&mut aux).unwrap();

        id += 1u32 + (number_of_aux_symbols as u32);
    }
    f.seek(SeekFrom::Start(pos))?;

    for section_id in 1..=sections_count {
        let mut buff = vec![0; 8usize];
        f.read(&mut buff).unwrap();
        let name = String::from_utf8(buff).unwrap().trim_matches(char::from(0)).to_string();
        let size_mem = f.read_u32::<LittleEndian>()?;
        let virt_addr = f.read_u32::<LittleEndian>()?;
        let size_raw = f.read_u32::<LittleEndian>()?;
        let raw_data = f.read_u32::<LittleEndian>()?;
        let reloc_ptr = f.read_u32::<LittleEndian>()?;
        let lines_ptr = f.read_u32::<LittleEndian>()?;
        let reloc_count = f.read_u16::<LittleEndian>()?;
        let lines_count = f.read_u16::<LittleEndian>()?;
        let characs = f.read_u32::<LittleEndian>()?;

        if name == ".text" {
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
                    assert_eq!(type_, 0x0006);

                    let patched = extract_address(&symbols[symtab_index as usize]);
                    let curr_addr = extract_address(&text_symbols[&section_id]) + offset;
                    let addr_diff = ((patched as i64) - (curr_addr as i64)) / 4;
 
                    buff[offset as usize]       = (buff[offset as usize] & 0b11111100) | ((addr_diff >> 22) & 0b11) as u8;
                    buff[(offset + 1) as usize] = ((addr_diff >> 14) & 0xff) as u8;
                    buff[(offset + 2) as usize] = ((addr_diff >> 6) & 0xff) as u8;
                    buff[(offset + 3) as usize] = (buff[(offset + 3) as usize] & 0b11) | ((addr_diff << 2) & 0b11111100) as u8;
                }
            }
            std::fs::write(format!("{}.bin", args[1]), buff)?;
            f.seek(SeekFrom::Start(pos))?;
        } else if name == ".data" {
            let pos = f.stream_position()?;

            f.seek(SeekFrom::Start(raw_data as u64))?;
            let mut buff = vec![0; size_raw as usize];
            f.read(&mut buff).unwrap();

            std::fs::write(format!("{}.bin", args[1]), buff)?;

            f.seek(SeekFrom::Start(pos))?;
        }
    }

    Ok(())
}

fn extract_address(arg: &str) -> u32 {
    u32::from_str_radix(&arg[4..], 16).unwrap()
}
