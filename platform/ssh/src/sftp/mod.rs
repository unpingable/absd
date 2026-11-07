//! Synchronous, bounded SFTP v3. This worker never acquires filesystem authority;
//! the SSH backend starts it with an ordinary restricted session binding.
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions, ReadDir};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
mod filesystem;
#[cfg(test)]
mod tests;
mod wire;
use wire::{Attributes, Fields};

const MAX_IO: usize = 64 * 1024;
const MAX_HANDLES: usize = 16;
type Result<T> = std::result::Result<T, u32>;

enum Handle {
    File { file: File, read: bool, write: bool },
    Directory(ReadDir),
}
struct Session {
    home: PathBuf,
    handles: BTreeMap<u64, Handle>,
    next: u64,
    initialized: bool,
}
impl Session {
    fn new(home: &Path) -> Self {
        Self {
            home: home.into(),
            handles: BTreeMap::new(),
            next: 1,
            initialized: false,
        }
    }
    fn capacity(&self) -> Result<()> {
        if self.handles.len() >= MAX_HANDLES || self.next == u64::MAX {
            Err(4)
        } else {
            Ok(())
        }
    }
    fn token(fields: &mut Fields<'_>) -> Result<u64> {
        let bytes = fields.string(256)?;
        if bytes.len() != 8 {
            return Err(4);
        }
        Ok(wire::decode::<u64>(bytes).map_err(|_| 4u32)?.0)
    }
    fn add(&mut self, id: u32, handle: Handle) -> Result<Vec<u8>> {
        self.capacity()?;
        let token = self.next;
        self.next = self.next.checked_add(1).ok_or(4u32)?;
        self.handles.insert(token, handle);
        let mut bytes = Vec::new();
        wire::encode(&mut bytes, &token);
        let mut reply = wire::response(102, id);
        wire::string(&mut reply, &bytes);
        Ok(reply)
    }
    fn dispatch(&mut self, body: &[u8]) -> io::Result<Vec<u8>> {
        if !self.initialized {
            if body.len() != 5 || body[0] != 1 || wire::decode::<u32>(&body[1..])?.0 < 3 {
                return Err(wire::invalid());
            }
            self.initialized = true;
            let mut reply = vec![2];
            wire::encode(&mut reply, &3u32);
            return Ok(reply);
        }
        if body.len() < 5 || body[0] == 1 {
            return Err(wire::invalid());
        }
        let id = wire::decode::<u32>(&body[1..])?.0;
        Ok(match self.request(body[0], id, Fields(&body[5..])) {
            Ok(reply) => reply,
            Err(code) => wire::status(id, code),
        })
    }
    fn open(&mut self, id: u32, mut fields: Fields<'_>) -> Result<Vec<u8>> {
        let path = filesystem::path(&self.home, fields.string(filesystem::MAX_PATH)?)?;
        let flags = fields.u32()?;
        let attrs = Attributes::parse(&mut fields)?;
        fields.finish()?;
        attrs.creation()?;
        if flags & !63 != 0
            || flags & 3 == 0
            || (flags & 4 != 0 && flags & 2 == 0)
            || (flags & (8 | 16) != 0 && flags & 2 == 0)
            || (flags & 32 != 0 && flags & 8 == 0)
        {
            return Err(5);
        }
        // The current filesystem adapter has no atomic append primitive.
        // Do not implement protocol APPEND as a racy length-then-write.
        if flags & 4 != 0 {
            return Err(8);
        }
        // Validate and reserve before create/truncate can change the filesystem.
        self.capacity()?;
        let read = flags & 1 != 0;
        let write = flags & 2 != 0;
        let file = OpenOptions::new()
            .read(read)
            .write(write)
            .create(flags & 8 != 0)
            .truncate(flags & 16 != 0)
            .create_new(flags & 32 != 0)
            .open(path)
            .map_err(filesystem::error)?;
        self.add(id, Handle::File { file, read, write })
    }
    fn read(&mut self, id: u32, mut fields: Fields<'_>) -> Result<Vec<u8>> {
        let token = Self::token(&mut fields)?;
        let offset = fields.u64()?;
        let size = fields.u32()? as usize;
        fields.finish()?;
        if size > MAX_IO {
            return Err(5);
        }
        // Read-ahead may cross the maximum writable file size or start
        // beyond EOF. Let the file return its final bytes or EOF normally.
        let Some(Handle::File {
            file, read: true, ..
        }) = self.handles.get_mut(&token)
        else {
            return Err(4);
        };
        file.seek(SeekFrom::Start(offset))
            .map_err(filesystem::error)?;
        let mut bytes = vec![0; size];
        let count = file.read(&mut bytes).map_err(filesystem::error)?;
        if count == 0 && size != 0 {
            return Ok(wire::status(id, 1));
        }
        let mut reply = wire::response(103, id);
        wire::string(&mut reply, &bytes[..count]);
        Ok(reply)
    }
    fn write(&mut self, id: u32, mut fields: Fields<'_>) -> Result<Vec<u8>> {
        let token = Self::token(&mut fields)?;
        let offset = fields.u64()?;
        let bytes = fields.string(MAX_IO)?;
        fields.finish()?;
        let Some(Handle::File {
            file, write: true, ..
        }) = self.handles.get_mut(&token)
        else {
            return Err(4);
        };
        filesystem::range(offset, bytes.len())?;
        file.seek(SeekFrom::Start(offset))
            .map_err(filesystem::error)?;
        file.write_all(bytes).map_err(filesystem::error)?;
        Ok(wire::status(id, 0))
    }
    fn setstat(&mut self, id: u32, mut fields: Fields<'_>, by_handle: bool) -> Result<Vec<u8>> {
        let (token, path) = if by_handle {
            (Some(Self::token(&mut fields)?), None)
        } else {
            (
                None,
                Some(filesystem::path(
                    &self.home,
                    fields.string(filesystem::MAX_PATH)?,
                )?),
            )
        };
        let attrs = Attributes::parse(&mut fields)?;
        fields.finish()?;
        attrs.size_only()?;
        if let Some(size) = attrs.size {
            filesystem::range(size, 0)?;
        }
        if let Some(token) = token {
            let Some(Handle::File { file, write, .. }) = self.handles.get(&token) else {
                return Err(4);
            };
            if let Some(size) = attrs.size {
                if !*write {
                    return Err(3);
                }
                file.set_len(size).map_err(filesystem::error)?;
                file.sync_all().map_err(filesystem::error)?;
            }
        } else if let Some(path) = path {
            if let Some(size) = attrs.size {
                let file = OpenOptions::new()
                    .write(true)
                    .open(path)
                    .map_err(filesystem::error)?;
                file.set_len(size).map_err(filesystem::error)?;
                file.sync_all().map_err(filesystem::error)?;
            } else {
                fs::metadata(path).map_err(filesystem::error)?;
            }
        }
        Ok(wire::status(id, 0))
    }
    fn readdir(&mut self, id: u32, mut fields: Fields<'_>) -> Result<Vec<u8>> {
        let token = Self::token(&mut fields)?;
        fields.finish()?;
        let Some(Handle::Directory(dir)) = self.handles.get_mut(&token) else {
            return Err(4);
        };
        let mut entries = Vec::new();
        for _ in 0..64 {
            let Some(entry) = dir.next() else {
                break;
            };
            let entry = entry.map_err(filesystem::error)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(4u32)?;
            if name.len() > 255 {
                return Err(4);
            }
            entries.push((
                PathBuf::from(name),
                entry.metadata().map_err(filesystem::error)?,
            ));
        }
        if entries.is_empty() {
            return Ok(wire::status(id, 1));
        }
        let mut reply = wire::response(104, id);
        wire::encode(&mut reply, &(entries.len() as u32));
        for (name, attrs) in entries {
            filesystem::name(&mut reply, &name, &attrs)?;
        }
        Ok(reply)
    }
    fn request(&mut self, kind: u8, id: u32, mut fields: Fields<'_>) -> Result<Vec<u8>> {
        match kind {
            3 => self.open(id, fields),
            4 => {
                let token = Self::token(&mut fields)?;
                fields.finish()?;
                let handle = self.handles.remove(&token).ok_or(4u32)?;
                if let Handle::File {
                    file, write: true, ..
                } = &handle
                {
                    file.sync_all().map_err(filesystem::error)?;
                }
                drop(handle);
                Ok(wire::status(id, 0))
            }
            5 => self.read(id, fields),
            6 => self.write(id, fields),
            7 | 17 => {
                let path = filesystem::path(&self.home, fields.string(filesystem::MAX_PATH)?)?;
                fields.finish()?;
                let attrs = if kind == 7 {
                    fs::symlink_metadata(path)
                } else {
                    fs::metadata(path)
                }
                .map_err(filesystem::error)?;
                let mut reply = wire::response(105, id);
                filesystem::attributes(&mut reply, &attrs);
                Ok(reply)
            }
            8 => {
                let token = Self::token(&mut fields)?;
                fields.finish()?;
                let Some(Handle::File { file, .. }) = self.handles.get(&token) else {
                    return Err(4);
                };
                let attrs = file.metadata().map_err(filesystem::error)?;
                let mut reply = wire::response(105, id);
                filesystem::attributes(&mut reply, &attrs);
                Ok(reply)
            }
            9 | 10 => self.setstat(id, fields, kind == 10),
            11 => {
                let path = filesystem::path(&self.home, fields.string(filesystem::MAX_PATH)?)?;
                fields.finish()?;
                self.capacity()?;
                let dir = fs::read_dir(path).map_err(filesystem::error)?;
                self.add(id, Handle::Directory(dir))
            }
            12 => self.readdir(id, fields),
            13 | 15 => {
                let path = filesystem::path(&self.home, fields.string(filesystem::MAX_PATH)?)?;
                fields.finish()?;
                if kind == 13 {
                    fs::remove_file(path)
                } else {
                    fs::remove_dir(path)
                }
                .map_err(filesystem::error)?;
                Ok(wire::status(id, 0))
            }
            14 => {
                let path = filesystem::path(&self.home, fields.string(filesystem::MAX_PATH)?)?;
                let attrs = Attributes::parse(&mut fields)?;
                fields.finish()?;
                attrs.creation()?;
                fs::create_dir(path).map_err(filesystem::error)?;
                Ok(wire::status(id, 0))
            }
            16 => {
                let path = filesystem::path(&self.home, fields.string(filesystem::MAX_PATH)?)?;
                fields.finish()?;
                let path = filesystem::canonical(&path).map_err(filesystem::error)?;
                let text = path.to_str().ok_or(4u32)?;
                if text.len() > filesystem::MAX_PATH {
                    return Err(4);
                }
                let mut reply = wire::response(104, id);
                wire::encode(&mut reply, &1u32);
                wire::string(&mut reply, text.as_bytes());
                wire::string(&mut reply, text.as_bytes());
                wire::encode(&mut reply, &0u32);
                Ok(reply)
            }
            18 => {
                let from = filesystem::path(&self.home, fields.string(filesystem::MAX_PATH)?)?;
                let to = filesystem::path(&self.home, fields.string(filesystem::MAX_PATH)?)?;
                fields.finish()?;
                filesystem::rename(&from, &to).map_err(filesystem::error)?;
                Ok(wire::status(id, 0))
            }
            _ => Err(8),
        }
    }
}

pub fn serve<R: Read, W: Write>(input: &mut R, output: &mut W, home: &Path) -> io::Result<()> {
    let mut session = Session::new(home);
    while let Some(frame) = wire::read_frame(input)? {
        match frame {
            wire::Frame::Packet(body) => {
                let reply = session.dispatch(&body)?;
                wire::write_frame(output, &reply)?;
            }
            wire::Frame::Oversized { kind, id } => {
                if session.initialized && kind != 1 && kind != 2 {
                    wire::write_frame(output, &wire::status(id, 5))?;
                }
                return Err(wire::invalid());
            }
        }
    }
    Ok(())
}
