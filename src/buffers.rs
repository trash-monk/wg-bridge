use std::{cell::RefCell, cmp::min, rc::Rc};

use log::info;

pub struct Buffer {
    inner: Option<Vec<u8>>,
    cap: usize,
    pool: Rc<RefCell<Vec<Vec<u8>>>>,
}

impl Buffer {
    pub fn truncate(&mut self, len: usize) {
        let new_len = min(len, self.cap);
        assert!(self.inner.as_ref().unwrap().capacity() >= self.cap);
        unsafe { self.inner.as_mut().unwrap().set_len(new_len) }
    }

    pub fn reset(&mut self) {
        self.truncate(self.cap)
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref().unwrap()
    }
}

impl AsMut<[u8]> for Buffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.inner.as_mut().unwrap()
    }
}

pub struct Pool {
    inner: Rc<RefCell<Vec<Vec<u8>>>>,
    cap: usize,
}

impl Pool {
    pub fn new(cnt: usize, bufsz: usize) -> Self {
        info!(cnt,bufsz; "allocating buffer pool");

        let mut bufs = Vec::new();
        for _ in 0..cnt {
            let mut buf = Vec::new();
            buf.reserve_exact(bufsz);
            buf.resize(bufsz, 0);
            bufs.push(buf);
        }
        Self { inner: Rc::new(RefCell::new(bufs)), cap: bufsz }
    }

    pub fn get(&mut self) -> Buffer {
        let mut buf = Buffer {
            inner: Some(self.inner.borrow_mut().pop().unwrap()),
            pool: Rc::clone(&self.inner),
            cap: self.cap,
        };
        buf.reset();
        buf
    }
}
