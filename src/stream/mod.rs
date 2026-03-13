use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{Result, StormError};

#[derive(Debug)]
pub struct FileStream {
    file: File,
    path: PathBuf,
    len: u64,
}

impl FileStream {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().read(true).write(false).open(&path)?;
        let len = file.metadata()?.len();
        Ok(Self { file, path, len })
    }

    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)?;
        Ok(Self { file, path, len: 0 })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        Ok(self.file.seek(pos)?)
    }

    pub fn position(&mut self) -> Result<u64> {
        self.seek(SeekFrom::Current(0))
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        self.file.read_exact(buf)?;
        Ok(())
    }

    pub fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.file.write_all(buf)?;
        let pos = self.file.stream_position()?;
        if pos > self.len {
            self.len = pos;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.file.flush()?;
        Ok(())
    }

    pub fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>> {
        self.ensure_range(offset, len as u64)?;
        self.file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len];
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    pub fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.ensure_range(offset, buf.len() as u64)?;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(buf)?;
        Ok(())
    }

    pub fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(buf)?;
        let end = offset.saturating_add(buf.len() as u64);
        if end > self.len {
            self.len = end;
        }
        Ok(())
    }

    pub fn ensure_range(&self, offset: u64, len: u64) -> Result<()> {
        let end = offset
            .checked_add(len)
            .ok_or(StormError::Bounds("offset + len overflow"))?;
        if end > self.len {
            return Err(StormError::Bounds("requested range exceeds file length"));
        }
        Ok(())
    }

    pub fn read_u16_le_at(&mut self, offset: u64) -> Result<u16> {
        let mut b = [0u8; 2];
        self.read_exact_at(offset, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }

    pub fn read_u32_le_at(&mut self, offset: u64) -> Result<u32> {
        let mut b = [0u8; 4];
        self.read_exact_at(offset, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    pub fn read_u64_le_at(&mut self, offset: u64) -> Result<u64> {
        let mut b = [0u8; 8];
        self.read_exact_at(offset, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }
}

#[cfg(test)]
mod tests {
    use std::io::SeekFrom;

    use tempfile::tempdir;

    use super::FileStream;

    #[test]
    fn read_write_seek_roundtrip() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("stream.bin");
        let mut s = FileStream::create(&p).unwrap();
        s.write_all(b"abcdef").unwrap();
        s.write_all_at(10, b"XY").unwrap();
        s.flush().unwrap();

        assert_eq!(s.len(), 12);
        s.seek(SeekFrom::Start(0)).unwrap();
        let mut first = [0u8; 6];
        s.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"abcdef");

        let part = s.read_at(10, 2).unwrap();
        assert_eq!(&part, b"XY");
        assert!(s.read_at(11, 2).is_err());
    }

    #[test]
    fn endian_helpers_are_little_endian() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("endian.bin");
        let mut s = FileStream::create(&p).unwrap();
        s.write_all(&[0x34, 0x12, 0x78, 0x56, 0xEF, 0xCD, 0xAB, 0x90])
            .unwrap();
        s.flush().unwrap();

        assert_eq!(s.read_u16_le_at(0).unwrap(), 0x1234);
        assert_eq!(s.read_u32_le_at(0).unwrap(), 0x5678_1234);
        assert_eq!(s.read_u64_le_at(0).unwrap(), 0x90AB_CDEF_5678_1234);
    }
}
