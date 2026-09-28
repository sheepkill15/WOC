//! Read-only executable metadata.
//!
//! Parses the PE resource section to find the VS_VERSIONINFO block without
//! loading or executing the file. Only headers and the resource section are
//! read, with fixed size limits, and malformed input simply yields `None`.

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const MAX_RESOURCE_SECTION: u64 = 16 * 1024 * 1024;
const RT_VERSION: u32 = 16;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutableInfo {
    pub file_name: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub company_name: Option<String>,
    #[serde(default)]
    pub product_name: Option<String>,
    #[serde(default)]
    pub file_description: Option<String>,
    #[serde(default)]
    pub product_version: Option<String>,
}

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2).map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4).map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_exact_at(file: &mut File, offset: u64, length: usize) -> Option<Vec<u8>> {
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut buffer = vec![0u8; length];
    file.read_exact(&mut buffer).ok()?;
    Some(buffer)
}

struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_size: u32,
    raw_pointer: u32,
}

/// Returns the raw resource section bytes and its RVA.
fn resource_section(file: &mut File) -> Option<(Vec<u8>, u32)> {
    let dos = read_exact_at(file, 0, 64)?;
    if &dos[0..2] != b"MZ" { return None; }
    let pe_offset = u32_at(&dos, 0x3C)? as u64;
    let header = read_exact_at(file, pe_offset, 24)?;
    if &header[0..4] != b"PE\0\0" { return None; }
    let section_count = u16_at(&header, 6)? as usize;
    let optional_size = u16_at(&header, 20)? as usize;
    if section_count == 0 || section_count > 96 || optional_size > 4096 { return None; }
    let optional = read_exact_at(file, pe_offset + 24, optional_size)?;
    let data_directories = match u16_at(&optional, 0)? {
        0x10b => 96,
        0x20b => 112,
        _ => return None,
    };
    let resource_rva = u32_at(&optional, data_directories + 2 * 8)?;
    if resource_rva == 0 { return None; }
    let table = read_exact_at(file, pe_offset + 24 + optional_size as u64, section_count * 40)?;
    let sections = (0..section_count).filter_map(|index| {
        let base = index * 40;
        Some(Section {
            virtual_size: u32_at(&table, base + 8)?,
            virtual_address: u32_at(&table, base + 12)?,
            raw_size: u32_at(&table, base + 16)?,
            raw_pointer: u32_at(&table, base + 20)?,
        })
    }).collect::<Vec<_>>();
    let section = sections.iter().find(|section| {
        let span = section.virtual_size.max(section.raw_size);
        resource_rva >= section.virtual_address && resource_rva < section.virtual_address.saturating_add(span)
    })?;
    let length = u64::from(section.raw_size).min(MAX_RESOURCE_SECTION) as usize;
    let data = read_exact_at(file, u64::from(section.raw_pointer), length)?;
    // Resource offsets are relative to the resource directory, which may not start the section.
    let start = (resource_rva - section.virtual_address) as usize;
    let data = data.get(start..)?.to_vec();
    Some((data, resource_rva))
}

/// Walks the resource tree: type RT_VERSION → first name → first language → data entry.
fn version_resource(resources: &[u8], resource_rva: u32) -> Option<&[u8]> {
    let mut offset = 0usize;
    for level in 0..3 {
        let named = u16_at(resources, offset + 12)? as usize;
        let ids = u16_at(resources, offset + 14)? as usize;
        let entries = offset + 16;
        let mut next = None;
        for index in 0..(named + ids).min(512) {
            let entry = entries + index * 8;
            let name = u32_at(resources, entry)?;
            let target = u32_at(resources, entry + 4)?;
            if level == 0 && (name & 0x8000_0000 != 0 || name != RT_VERSION) { continue; }
            next = Some(target);
            break;
        }
        let target = next?;
        if level < 2 {
            if target & 0x8000_0000 == 0 { return None; }
            offset = (target & 0x7FFF_FFFF) as usize;
        } else {
            if target & 0x8000_0000 != 0 { return None; }
            let data_entry = target as usize;
            let rva = u32_at(resources, data_entry)?;
            let size = u32_at(resources, data_entry + 4)? as usize;
            let start = rva.checked_sub(resource_rva)? as usize;
            return resources.get(start..start.checked_add(size)?);
        }
    }
    None
}

fn utf16_string(data: &[u8], offset: usize, max_end: usize) -> Option<(String, usize)> {
    let mut units = Vec::new();
    let mut position = offset;
    while position + 1 < max_end {
        let unit = u16_at(data, position)?;
        position += 2;
        if unit == 0 { return Some((String::from_utf16_lossy(&units), position)); }
        units.push(unit);
        if units.len() > 1024 { return None; }
    }
    None
}

fn align4(value: usize) -> usize { (value + 3) & !3 }

/// A version-info block: key, value bytes, and child block range.
struct Block<'a> {
    key: String,
    value: &'a [u8],
    value_is_text: bool,
    children: std::ops::Range<usize>,
    end: usize,
}

fn parse_block(data: &[u8], offset: usize) -> Option<Block<'_>> {
    let length = u16_at(data, offset)? as usize;
    let value_length = u16_at(data, offset + 2)? as usize;
    let value_type = u16_at(data, offset + 4)?;
    if length < 6 { return None; }
    let end = (offset + length).min(data.len());
    let (key, after_key) = utf16_string(data, offset + 6, end)?;
    let value_start = align4(after_key);
    let value_bytes = if value_type == 1 { value_length * 2 } else { value_length };
    let value_end = (value_start + value_bytes).min(end);
    let value = data.get(value_start.min(end)..value_end)?;
    let children_start = align4(value_end).min(end);
    Some(Block { key, value, value_is_text: value_type == 1, children: children_start..end, end: align4(end) })
}

fn text_value(block: &Block<'_>) -> Option<String> {
    if !block.value_is_text { return None; }
    let units = block.value.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|unit| *unit != 0).collect::<Vec<_>>();
    let text = String::from_utf16_lossy(&units).trim().to_owned();
    (!text.is_empty()).then_some(text)
}

fn string_table_values(data: &[u8]) -> Vec<(String, String)> {
    let mut values = Vec::new();
    let Some(root) = parse_block(data, 0) else { return values; };
    if root.key != "VS_VERSION_INFO" { return values; }
    let mut position = root.children.start;
    while position < root.children.end {
        let Some(child) = parse_block(data, position) else { break; };
        if child.key == "StringFileInfo" {
            let mut table_position = child.children.start;
            while table_position < child.children.end {
                let Some(table) = parse_block(data, table_position) else { break; };
                let mut string_position = table.children.start;
                while string_position < table.children.end {
                    let Some(string) = parse_block(data, string_position) else { break; };
                    if let Some(value) = text_value(&string) { values.push((string.key.clone(), value)); }
                    if string.end <= string_position { break; }
                    string_position = string.end;
                }
                if !values.is_empty() { return values; }
                if table.end <= table_position { break; }
                table_position = table.end;
            }
        }
        if child.end <= position { break; }
        position = child.end;
    }
    values
}

/// Reads version metadata from a PE file without executing or loading it.
pub fn read_executable_info(path: &Path) -> Option<ExecutableInfo> {
    let mut file = File::open(path).ok()?;
    let size_bytes = file.metadata().ok()?.len();
    let file_name = path.file_name()?.to_string_lossy().into_owned();
    let mut info = ExecutableInfo { file_name, size_bytes, ..Default::default() };
    if let Some((resources, rva)) = resource_section(&mut file) {
        if let Some(version) = version_resource(&resources, rva) {
            for (key, value) in string_table_values(version) {
                match key.as_str() {
                    "CompanyName" => info.company_name = Some(value),
                    "ProductName" => info.product_name = Some(value),
                    "FileDescription" => info.file_description = Some(value),
                    "ProductVersion" => info.product_version = Some(value),
                    _ => {}
                }
            }
        }
    }
    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16z(text: &str) -> Vec<u8> {
        text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
    }

    fn block(key: &str, value: &[u8], text: bool, children: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![0u8; 6];
        out.extend(utf16z(key));
        while out.len() % 4 != 0 { out.push(0); }
        out.extend_from_slice(value);
        while out.len() % 4 != 0 { out.push(0); }
        for child in children { out.extend_from_slice(child); while out.len() % 4 != 0 { out.push(0); } }
        let length = out.len() as u16;
        let value_length = if text { (value.len() / 2) as u16 } else { value.len() as u16 };
        out[0..2].copy_from_slice(&length.to_le_bytes());
        out[2..4].copy_from_slice(&value_length.to_le_bytes());
        out[4..6].copy_from_slice(&(text as u16).to_le_bytes());
        out
    }

    #[test]
    fn parses_string_file_info() {
        let company = block("CompanyName", &utf16z("Example Co"), true, &[]);
        let product = block("ProductName", &utf16z("Example App"), true, &[]);
        let table = block("040904b0", &[], true, &[company, product]);
        let string_info = block("StringFileInfo", &[], true, &[table]);
        let root = block("VS_VERSION_INFO", &[0u8; 52], false, &[string_info]);
        let values = string_table_values(&root);
        assert_eq!(values, vec![("CompanyName".into(), "Example Co".into()), ("ProductName".into(), "Example App".into())]);
    }

    #[test]
    fn malformed_or_missing_files_are_harmless() {
        assert!(read_executable_info(Path::new(r"C:\definitely\missing.exe")).is_none());
        let path = std::env::temp_dir().join(format!("orphan-cleaner-pe-{}.exe", std::process::id()));
        std::fs::write(&path, b"MZ not really a PE").unwrap();
        let info = read_executable_info(&path).unwrap();
        assert!(info.company_name.is_none());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn reads_system_executable_when_present() {
        let candidates = ["notepad.exe", "conhost.exe", "cmd.exe"].map(|name| std::path::PathBuf::from(r"C:\Windows\System32").join(name));
        let existing = candidates.iter().filter(|path| path.is_file()).collect::<Vec<_>>();
        if existing.is_empty() { return; }
        let infos = existing.iter().filter_map(|path| read_executable_info(path)).collect::<Vec<_>>();
        assert!(infos.iter().any(|info| info.company_name.is_some() || info.product_name.is_some()), "{infos:?}");
    }
}
