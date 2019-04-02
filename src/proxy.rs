use httparse::{Response, EMPTY_HEADER};
use mio::net::TcpStream;
use result::{Error, Kind, Result};
use std::io::{Read, Write};
use std::net::TcpStream as StdTcpStream;
use url::Url;

#[derive(Debug, Clone, Copy)]
pub enum AuthType {
    None,
    Basic,
    Digest,
}

#[derive(Debug, Clone)]
pub struct Proxy {
    url: Url,
    auth_type: AuthType,
}

impl Proxy {
    pub fn new(url: Url) -> Self {
        Proxy {
            url,
            auth_type: AuthType::None,
        }
    }

    pub fn new_with_auth(url: Url, auth_type: AuthType) -> Self {
        Proxy { url, auth_type }
    }

    pub fn set_auth_type(&mut self, auth_type: AuthType) {
        self.auth_type = auth_type;
    }

    pub fn set_username(&mut self, username: &str) {
        self.url.set_username(username);
    }

    pub fn set_password(&mut self, password: &str) {
        self.url.set_password(Some(password));
    }

    pub fn connect(&self, url: &Url) -> Result<TcpStream> {
        let mut stream = StdTcpStream::connect(&self.url)?;

        let host = format!(
            "{}:{}",
            url.host_str().unwrap(),
            url.port_or_known_default().unwrap_or(80)
        );
        let connect = match self.auth_type {
            AuthType::None => format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n",
                host, host
            ),
            AuthType::Basic => unimplemented!(),
            AuthType::Digest => unimplemented!(),
        };

        debug!("{}", connect);
        stream.write(connect.as_ref())?;

        let mut buf = [0; 1024];

        stream.read(&mut buf)?;

        let mut headers = [EMPTY_HEADER; 32];
        let mut res = Response::new(&mut headers);
        res.parse(&mut buf)?;

        match res.code {
            Some(code) if code >= 200 && code < 300 => Ok(TcpStream::from_stream(stream)?),
            Some(code) if code == 401 => Err(Error::new(Kind::Proxy, "proxy unauthorized.")),
            Some(code) if code == 407 => {
                Err(Error::new(Kind::Proxy, "proxy required authorization."))
            }
            _ => Err(Error::new(Kind::Proxy, "unexpect responsecode from proxy.")),
        }
    }
}
