use std::{cell::RefCell, cmp::min, rc::Rc};

use log::{info, warn};

pub struct Buffer {
    inner: Option<Vec<u8>>,
    cap: usize,
    pool: Rc<RefCell<Vec<Vec<u8>>>>,
}

impl Buffer {
    fn allocate(buf_sz: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.reserve_exact(buf_sz);
        buf.resize(buf_sz, 0);
        buf
    }

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

impl Drop for Buffer {
    fn drop(&mut self) {
        let len = self.pool.borrow().len();
        let cap = self.pool.borrow().capacity();
        if len < cap {
            self.pool.borrow_mut().push(self.inner.take().unwrap());
        }
        assert_eq!(cap, self.pool.borrow().capacity());
    }
}

pub struct Pool {
    inner: Rc<RefCell<Vec<Vec<u8>>>>,
    buf_sz: usize,
}

impl Pool {
    pub fn new(buf_cnt: usize, buf_sz: usize) -> Self {
        info!(buf_cnt,buf_sz; "allocating buffer pool");

        let mut bufs = Vec::new();
        bufs.reserve_exact(buf_cnt);
        for _ in 0..buf_cnt {
            bufs.push(Buffer::allocate(buf_sz));
        }
        Self {
            inner: Rc::new(RefCell::new(bufs)),
            buf_sz,
        }
    }

    pub fn get(&mut self) -> Buffer {
        let buf = match self.inner.borrow_mut().pop() {
            Some(x) => x,
            None => {
                warn!("buffer pool exhausted");
                Buffer::allocate(self.buf_sz)
            }
        };

        let mut out = Buffer {
            inner: Some(buf),
            pool: Rc::clone(&self.inner),
            cap: self.buf_sz,
        };
        out.reset();
        out
    }

    pub fn available(&self) -> usize {
        let len = self.inner.borrow().len();
        let cap = self.inner.borrow().capacity();
        cap - len
    }
}
