use std::cmp::min;

use log::info;

#[derive(Debug)]
pub struct Buffer {
    inner: Vec<u8>,
    cap: usize,
}

impl Buffer {
    pub fn new(sz: usize) -> Self {
        let mut buf = Vec::new();
        buf.reserve_exact(sz);
        buf.resize(sz, 0);
        Self {
            inner: buf,
            cap: sz,
        }
    }

    pub fn truncate(&mut self, len: usize) {
        let new_len = min(len, self.cap);
        assert!(self.inner.capacity() >= self.cap);
        unsafe { self.inner.set_len(new_len) }
    }

    pub fn reset(&mut self) {
        assert!(self.inner.capacity() >= self.cap);
        unsafe { self.inner.set_len(self.cap) }
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl AsMut<[u8]> for Buffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

pub struct Pool {
    inner: Vec<Buffer>,
}

impl Pool {
    pub fn new(cnt: usize, bufsz: usize) -> Self {
        info!(cnt,bufsz; "allocating buffer pool");

        let mut inner = Vec::new();
        for _ in 0..cnt {
            inner.push(Buffer::new(bufsz));
        }
        Self { inner }
    }

    pub fn put(&mut self, mut buf: Buffer) {
        buf.reset();
        self.inner.push(buf);
    }

    pub fn get(&mut self) -> Option<Buffer> {
        let out = self.inner.pop();
        if out.is_none() {
            info!("stall on empty buffer pool")
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        let empty = self.inner.is_empty();
        if empty {
            info!("empty buffer pool")
        }
        empty
    }
}
