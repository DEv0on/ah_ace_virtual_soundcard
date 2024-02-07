use std::sync::Mutex;
use crate::network_adapter::{ACEAdapter, Adapter};

pub trait Client {
    fn new() -> Self;
}

pub struct MainClient {
    pub adapter: Mutex<ACEAdapter>,
}

impl Client for MainClient {
    fn new() -> MainClient {
        Self {
            adapter: Mutex::from(ACEAdapter::new())
        }
    }
}
