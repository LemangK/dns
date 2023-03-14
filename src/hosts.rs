use crate::DomainString;
use log::*;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::io::BufRead;
use std::net::IpAddr;
use std::ops::Add;
use std::path::Path;
use std::time::{Duration, Instant};

/// Global instance
static HOSTS: Lazy<Mutex<Hosts>> = Lazy::new(|| Mutex::new(Hosts::new()));
/// Cache system hosts age
const CACHE_MAX_AGE: Duration = Duration::from_secs(5);

/// Query system hosts
///
/// * name      domain
pub fn get(name: &str) -> Option<IpAddr> {
    let mut hosts = HOSTS.lock();
    if Instant::now() > hosts.expire {
        hosts.reload();
    }
    hosts.inner.get(name).map(|e| *e)
}

struct Hosts {
    inner: HashMap<DomainString, IpAddr>,
    expire: Instant,
}

#[cfg(unix)]
fn hosts_path() -> Option<&'static str> {
    Some("/etc/hosts")
}

#[cfg(windows)]
fn hosts_path() -> Option<std::path::PathBuf> {
    let system_root = std::env::var_os("SystemRoot")?;
    let system_root = Path::new(&system_root);
    Some(system_root.join("System32\\drivers\\etc\\hosts"))
}

impl Hosts {
    fn new() -> Self {
        let mut hosts = Self {
            inner: Default::default(),
            expire: Instant::now(),
        };
        hosts.reload();
        hosts
    }

    fn reload(&mut self) {
        #[cfg(any(unix, windows))]
        if let Some(path) = hosts_path() {
            self.inner.clear();
            if let Err(err) = self.read_system_hosts(path) {
                error!("load system hosts failed {:?}", err)
            } else {
                self.expire = Instant::now().add(CACHE_MAX_AGE);
            }
        }
    }

    #[cfg(any(unix, windows))]
    fn read_system_hosts<S: AsRef<Path>>(&mut self, path: S) -> io::Result<()> {
        use std::fs::File;
        use std::io::BufReader;

        for line in BufReader::new(File::open(path)?).lines() {
            let line = line?;

            let line = line.split('#').next().unwrap().trim();
            // ignore comment eg. #comment
            if line.is_empty() {
                continue;
            }

            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 2 {
                continue;
            }

            let ip = match fields[0].parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(_) => {
                    warn!("could not parse on ip from hosts file");
                    continue;
                }
            };

            for domain in fields.iter().skip(1).map(|domain| domain.to_lowercase()) {
                if crate::msg::Labels::verify(&domain) {
                    debug!("load system dns domain: {:?}, ip: {:?}", domain, ip,);
                    self.inner.insert(DomainString::from(domain), ip.clone());
                }
            }
        }

        Ok(())
    }
}
