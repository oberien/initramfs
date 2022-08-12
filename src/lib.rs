#![no_std]

// specification: https://www.kernel.org/doc/Documentation/driver-api/early-userspace/buffer-format.rst

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
    InvalidCpioHeaderMagic([u8; 6]),
    /// (header property name, property bytes)
    InvalidHex(&'static str, [u8; 8]),
    /// (index, invalid align byte)
    InvalidAlign(usize, u8),
    InvalidChecksumNotZero(u32),
    /// (expected, actual)
    InvalidChecksum(u32, u32),
    /// (expected, actual)
    InvalidFilenameLength(u32, u32),
    UnexpectedEof,
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidCpioHeaderMagic(magic) => write!(f, "invalid cpio_header magic value {}", String::from_utf8_lossy(magic)),
            Error::InvalidHex(prop, value) => write!(f, "invalid cpio_header hex value for {prop}: {value:x?}"),
            Error::InvalidAlign(index, value) => write!(f, "invalid alignment byte {value:#x} at index {index}"),
            Error::InvalidChecksumNotZero(actual) => write!(f, "invalid checksum: expected no checksum = 0 but cpio_header has {actual}"),
            Error::InvalidChecksum(expected, actual) => write!(f, "invalid checksum: expected {expected}, got {actual}"),
            Error::InvalidFilenameLength(expected, actual) => write!(f, "invalid filename length: expected {expected}, got {actual}"),
            Error::UnexpectedEof => write!(f, "unexpected EOF"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Initramfs {
    pub archives: Vec<MaybeRawArchive>,
}

impl Initramfs {
    pub fn new() -> Initramfs {
        Initramfs { archives: Vec::new() }
    }

    pub fn add_archive(&mut self, archive: Archive) {
        self.archives.push(MaybeRawArchive::Parsed(archive));
    }

    pub fn add_raw_archive(&mut self, archive: Vec<u8>) {
        self.archives.push(MaybeRawArchive::Raw(archive));
    }

    pub fn parse(initramfs: &Vec<u8>) -> Result<Initramfs, Error> {
        log::trace!("Initramfs::parse");
        let mut archives = Vec::new();
        let mut index = 0;
        while index < initramfs.len() {
            index = parse_leading_zeroes(initramfs, index);
            let (archive, idx) = Archive::parse(initramfs, index)?;
            index = idx;
            archives.push(MaybeRawArchive::Parsed(archive));
        }
        Ok(Initramfs { archives })
    }

    pub fn write(&self, data: &mut Vec<u8>) {
        for archive in &self.archives {
            match archive {
                MaybeRawArchive::Parsed(archive) => archive.write(data),
                MaybeRawArchive::Raw(raw) => data.extend_from_slice(raw),
            }
            // The spec doesn't state it, but uncompressed archives must be 4-byte-aligned.
            // Compressed archives can directly follow each other unaligned.
            // We always align archives as we don't know if an archive is compressed or not.
            write_align_to_4(data);
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MaybeRawArchive {
    Parsed(Archive),
    Raw(Vec<u8>),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Archive {
    pub files: Vec<File>,
}

impl Archive {
    pub fn new() -> Archive {
        Archive { files: Vec::new() }
    }

    pub fn add_file(&mut self, mut file: File) {
        match self.files.last() {
            Some(file) if file.filename == b"TRAILER!!!" => panic!("Archive::add_file called after trailer"),
            _ => (),
        }
        file.header.ino = self.files.len() as u32;
        self.files.push(file);
    }

    pub fn add_trailer(&mut self) {
        self.files.push(File::new("TRAILER!!!".to_string(), Vec::new()));
    }

    pub fn parse(data: &Vec<u8>, mut index: usize) -> Result<(Archive, usize), Error> {
        log::trace!("Archive::parse {index}");
        let mut files = Vec::new();
        while index < data.len() {
            let (file, idx) = File::parse(data, index)?;
            index = idx;
            files.push(file);
            if files.last().unwrap().filename == b"TRAILER!!!" {
                break;
            }
        }
        Ok((Archive { files }, index))
    }

    pub fn write(&self, data: &mut Vec<u8>) {
        for file in &self.files {
            file.write(data);
        }
        write_align_to(data, 4096);
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct File {
    pub header: CpioHeader,
    pub filename: Vec<u8>,
    pub data: Vec<u8>,
}

impl File {
    pub fn new(filename: String, data: Vec<u8>) -> File {
        assert!(!filename.ends_with('/') || data.is_empty());
        File {
            header: CpioHeader {
                magic: CpioHeaderMagic::WithoutChecksum,
                ino: 0,
                // directory or regular file
                mode: if filename.ends_with('/') { 0o40755 } else { 0o100644 },
                uid: 0,
                gid: 0,
                nlink: 0,
                mtime: 0,
                filesize: data.len() as u32,
                maj: 0,
                min: 1,
                rmaj: 0,
                rmin: 0,
                namesize: filename.len() as u32 + 1,
                chksum: 0,
            },
            filename: filename.into_bytes(),
            data,
        }
    }

    pub fn parse(data: &Vec<u8>, mut index: usize) -> Result<(File, usize), Error> {
        log::trace!("File::parse {index}");
        index = parse_align_to_4(data, index)?;
        let array = data.get(index..index+110).ok_or(Error::UnexpectedEof)?
            .try_into().unwrap();
        index += 110;
        let cpio_header = RawCpioHeader::new(array);
        let header = CpioHeader::parse(&cpio_header)?;
        log::trace!("{header:#?}");
        let filename: Vec<_> = data.get(index..).ok_or(Error::UnexpectedEof)?
            .iter().copied()
            .take_while(|&b| b != 0)
            .collect();
        index += filename.len();
        if filename.len() as u32 + 1 != header.namesize {
            return Err(Error::InvalidFilenameLength(filename.len() as u32 + 1, header.namesize));
        }
        assert_eq!(0, *data.get(index).ok_or(Error::UnexpectedEof)?);
        index += 1;
        index = parse_align_to_4(data, index)?;
        let mut checksum: u32 = 0;
        let data: Vec<_> = data.get(index..index + header.filesize as usize)
            .ok_or(Error::UnexpectedEof)?
            .iter().copied()
            .inspect(|&b| checksum += b as u32)
            .collect();
        index += data.len();
        // verify checksum
        match header.magic {
            CpioHeaderMagic::WithoutChecksum => if header.chksum != 0 {
                return Err(Error::InvalidChecksumNotZero(header.chksum));
            },
            CpioHeaderMagic::WithChecksum => if header.chksum != checksum {
                return Err(Error::InvalidChecksum(header.chksum, checksum));
            }
        }

        log::debug!("parsed file {:?} size {}", String::from_utf8_lossy(&filename), header.filesize);
        Ok((File { header, filename, data }, index))
    }

    pub fn write(&self, data: &mut Vec<u8>) {
        write_align_to_4(data);
        let cpio_header = self.header.to_cpio_header();
        cpio_header.write(data);
        data.extend_from_slice(&self.filename);
        data.push(0);
        write_align_to_4(data);
        data.extend_from_slice(&self.data);
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CpioHeaderMagic {
    WithoutChecksum,
    WithChecksum,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CpioHeader {
    pub magic: CpioHeaderMagic,
    pub ino: u32,
    // https://askubuntu.com/a/423678
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub mtime: u32,
    pub filesize: u32,
    pub maj: u32,
    pub min: u32,
    pub rmaj: u32,
    pub rmin: u32,
    pub namesize: u32,
    pub chksum: u32,
}

impl CpioHeader {
    pub fn parse(header: &RawCpioHeader) -> Result<CpioHeader, Error> {
        log::trace!("CpioHeader::parse");
        Ok(CpioHeader {
            magic: match &header.magic {
                b"070701" => CpioHeaderMagic::WithoutChecksum,
                b"070702" => CpioHeaderMagic::WithChecksum,
                _ => return Err(Error::InvalidCpioHeaderMagic(header.magic)),
            },
            ino: parse_hex_be_u32("ino", header.ino)?,
            mode: parse_hex_be_u32("mode", header.mode)?,
            uid: parse_hex_be_u32("uid", header.uid)?,
            gid: parse_hex_be_u32("gid", header.gid)?,
            nlink: parse_hex_be_u32("nlink", header.nlink)?,
            mtime: parse_hex_be_u32("mtime", header.mtime)?,
            filesize: parse_hex_be_u32("filesize", header.filesize)?,
            maj: parse_hex_be_u32("maj", header.maj)?,
            min: parse_hex_be_u32("min", header.min)?,
            rmaj: parse_hex_be_u32("rmaj", header.rmaj)?,
            rmin: parse_hex_be_u32("rmin", header.rmin)?,
            namesize: parse_hex_be_u32("namesize", header.namesize)?,
            chksum: parse_hex_be_u32("chksum", header.chksum)?,
        })
    }

    pub fn to_cpio_header(&self) -> RawCpioHeader {
        RawCpioHeader {
            magic: match self.magic {
                CpioHeaderMagic::WithoutChecksum => *b"070701",
                CpioHeaderMagic::WithChecksum => *b"070702",
            },
            ino: to_hex_be_u32(self.ino),
            mode: to_hex_be_u32(self.mode),
            uid: to_hex_be_u32(self.uid),
            gid: to_hex_be_u32(self.gid),
            nlink: to_hex_be_u32(self.nlink),
            mtime: to_hex_be_u32(self.mtime),
            filesize: to_hex_be_u32(self.filesize),
            maj: to_hex_be_u32(self.maj),
            min: to_hex_be_u32(self.min),
            rmaj: to_hex_be_u32(self.rmaj),
            rmin: to_hex_be_u32(self.rmin),
            namesize: to_hex_be_u32(self.namesize),
            chksum: to_hex_be_u32(self.chksum),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RawCpioHeader {
    pub magic: [u8; 6],
    pub ino: [u8; 8],
    pub mode: [u8; 8],
    pub uid: [u8; 8],
    pub gid: [u8; 8],
    pub nlink: [u8; 8],
    pub mtime: [u8; 8],
    pub filesize: [u8; 8],
    pub maj: [u8; 8],
    pub min: [u8; 8],
    pub rmaj: [u8; 8],
    pub rmin: [u8; 8],
    pub namesize: [u8; 8],
    pub chksum: [u8; 8],
}

impl RawCpioHeader {
    pub fn new(data: [u8; 110]) -> RawCpioHeader {
        log::trace!("RawCpioHeader::new");
        RawCpioHeader {
            magic: data[0..6].try_into().unwrap(),
            ino: data[6..14].try_into().unwrap(),
            mode: data[14..22].try_into().unwrap(),
            uid: data[22..30].try_into().unwrap(),
            gid: data[30..38].try_into().unwrap(),
            nlink: data[38..46].try_into().unwrap(),
            mtime: data[46..54].try_into().unwrap(),
            filesize: data[54..62].try_into().unwrap(),
            maj: data[62..70].try_into().unwrap(),
            min: data[70..78].try_into().unwrap(),
            rmaj: data[78..86].try_into().unwrap(),
            rmin: data[86..94].try_into().unwrap(),
            namesize: data[94..102].try_into().unwrap(),
            chksum: data[102..110].try_into().unwrap(),
        }
    }

    pub fn write(&self, data: &mut Vec<u8>) {
        data.extend_from_slice(&self.magic);
        data.extend_from_slice(&self.ino);
        data.extend_from_slice(&self.mode);
        data.extend_from_slice(&self.uid);
        data.extend_from_slice(&self.gid);
        data.extend_from_slice(&self.nlink);
        data.extend_from_slice(&self.mtime);
        data.extend_from_slice(&self.filesize);
        data.extend_from_slice(&self.maj);
        data.extend_from_slice(&self.min);
        data.extend_from_slice(&self.rmaj);
        data.extend_from_slice(&self.rmin);
        data.extend_from_slice(&self.namesize);
        data.extend_from_slice(&self.chksum);
    }
}

fn parse_leading_zeroes(data: &Vec<u8>, mut index: usize) -> usize {
    while let Some(0) = data.get(index) {
        index += 1;
    }
    index
}

fn parse_align_to_4(data: &Vec<u8>, index: usize) -> Result<usize, Error> {
    let new_index = 4 * ((index + 3) / 4);
    for (i, align) in data.get(index..new_index).into_iter().flatten().enumerate() {
        if *align != 0 {
            return Err(Error::InvalidAlign(index + i, *align));
        }
    }
    Ok(new_index)
}

fn write_align_to_4(data: &mut Vec<u8>) {
    write_align_to(data, 4);
}

fn write_align_to(data: &mut Vec<u8>, align_to: usize) {
    let new_len = align_to * ((data.len() + (align_to-1)) / align_to);
    assert!(new_len >= data.len());
    data.resize(new_len, 0);
}

fn parse_hex_be_u32(property: &'static str, data: [u8; 8]) -> Result<u32, Error> {
    let parse_hex_nibble = |byte: u8| {
        if b'0' <= byte && byte <= b'9' {
            Ok((byte - b'0') as u32)
        } else if b'a' <= byte && byte <= b'f' {
            Ok((byte - b'a' + 10) as u32)
        } else if b'A' <= byte && byte <= b'F' {
            Ok((byte - b'A' + 10) as u32)
        } else {
            Err(Error::InvalidHex(property, data))
        }
    };
    let a = parse_hex_nibble(data[0])?;
    let b = parse_hex_nibble(data[1])?;
    let c = parse_hex_nibble(data[2])?;
    let d = parse_hex_nibble(data[3])?;
    let e = parse_hex_nibble(data[4])?;
    let f = parse_hex_nibble(data[5])?;
    let g = parse_hex_nibble(data[6])?;
    let h = parse_hex_nibble(data[7])?;
    Ok(
        (a << 28) | (b << 24) | (c << 20) | (d << 16)
        | (e << 12) | (f << 8) | (g << 4) | h
    )
}

fn to_hex_be_u32(data: u32) -> [u8; 8] {
    let mut array = [0; 8];
    hex::encode_to_slice(data.to_be_bytes(), &mut array).unwrap();
    array
}
