use core::fmt;
use core::fmt::{Display, Formatter};
use core::str::Chars;

/// The `.netrc` machine info
#[derive(Debug, Default, Eq, PartialEq, Clone)]
pub struct Machine {
    /// Identify a remote machine name, None is `default`
    pub name: Option<String>,
    /// Identify a user on the remote machine
    pub login: Option<String>,
    /// a password
    pub password: Option<String>,
    /// an additional account password
    pub account: Option<String>,
}

impl Display for Machine {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        macro_rules! write_key {
            ($key:expr, $fmt:expr, $default:expr) => {
                match &$key {
                    None => write!(f, $default),
                    Some(val) => write!(f, $fmt, val),
                }
            };
        }

        write_key!(self.name, "machine {}", "default")?;
        write_key!(self.login, " login {}", "")?;
        write_key!(self.password, " password {}", "")?;
        write_key!(self.account, " account {}", "")?;

        Ok(())
    }
}

/// Netrc represents a `.netrc` file struct
#[derive(Debug, Default)]
pub struct Netrc {
    /// machine name and one machine info are paired
    pub machines: Vec<Machine>,
    /// macro name and a list cmd are paired
    pub macdefs: Vec<(String, Vec<String>)>,
    /// support collecting unknown entry when parsing for some consumed conditions
    pub unknown_entries: Vec<String>,
}

/// Position saves row and column number, index is starting from 1
#[derive(Debug, Copy, Clone)]
pub struct Position(pub usize, pub usize);

/// Error occurs when parsing `.netrc` text
#[derive(Debug)]
pub enum Error {
    /// EOF occurs when read unexpected eof
    EOF,
    /// IllegalFormat occurs when meet mistake format
    IllegalFormat(Position, String),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::EOF => write!(f, "End of data: EOF"),
            Error::IllegalFormat(pos, s) => write!(f, "Illegal format in {} {}", pos, s.as_str()),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

impl Netrc {
    /// Parse a `Netrc` format str.
    /// If pass true to `unknown_entries`, it will collect unknown entries.
    ///
    /// # Examples
    ///
    /// ```
    /// use netrc_rs::{Netrc, Machine};
    ///
    /// let input = String::from("machine example.com login foo password bar");
    /// let netrc = Netrc::parse(input, false).unwrap();
    /// assert_eq!(netrc.machines, vec![ Machine {
    /// name: Some("example.com".to_string()),
    /// account: None,
    /// login: Some("foo".to_string()),
    /// password: Some("bar".to_string()),
    /// }]);
    /// assert_eq!(netrc.machines[0].to_string(), "machine example.com login foo password bar".to_string());
    /// ```
    pub fn parse<T: AsRef<str>>(buf: T, unknown_entries: bool) -> Result<Netrc> {
        Self::parse_borrow(&buf, unknown_entries)
    }

    /// Parse a `Netrc` format str with borrowing.
    ///
    /// If pass true to `unknown_entries`, it will collect unknown entries.
    ///
    /// # Examples
    ///
    /// ```
    /// use netrc_rs::{Netrc, Machine};
    ///
    /// let input = String::from("machine 例子.com login foo password bar");
    /// let netrc = Netrc::parse_borrow(&input, false).unwrap();
    /// assert_eq!(netrc.machines, vec![Machine {
    /// name: Some("例子.com".to_string()),
    /// account: None,
    /// login: Some("foo".to_string()),
    /// password: Some("bar".to_string()),
    /// }]);
    /// assert_eq!(netrc.machines[0].to_string(), "machine 例子.com login foo password bar".to_string());
    /// ```
    pub fn parse_borrow<T: AsRef<str>>(buf: &T, unknown_entries: bool) -> Result<Netrc> {
        let mut netrc = Netrc::default();
        let mut lexer = Lexer::new::<T>(buf);
        let mut count = MachineCount::default();
        loop {
            match lexer.next_token() {
                Err(Error::EOF) => break,
                Err(err) => return Err(err),
                Ok(tok) => {
                    netrc.parse_entry::<T>(&mut lexer, &tok, &mut count, unknown_entries)?;
                }
            }
        }
        Ok(netrc)
    }

    fn parse_entry<T: AsRef<str>>(
        &mut self,
        lexer: &mut Lexer,
        item: &Token,
        count: &mut MachineCount,
        unknown_entries: bool,
    ) -> Result<()> {
        match item {
            Token::Machine => {
                let host_name = lexer.next_token()?;
                self.machines.push(Default::default());
                self.machines[count.machine].name = Some(host_name.to_string());
                count.machine += 1;
                Ok(())
            }

            Token::Default => {
                self.machines.push(Default::default());
                count.machine += 1;
                Ok(())
            }

            Token::Login => {
                let name = lexer.next_token()?.to_string();
                count.login += 1;
                if count.login > count.machine {
                    return Err(Error::IllegalFormat(
                        lexer.tokens.position(),
                        "login must follow machine".to_string(),
                    ));
                } else {
                    let last = self.machines.len() - 1;
                    self.machines[last].login = Some(name)
                }
                Ok(())
            }

            Token::Password => {
                let name = lexer.next_token()?.to_string();
                count.password += 1;
                if count.password > count.machine {
                    return Err(Error::IllegalFormat(
                        lexer.tokens.position(),
                        "password must follow machine".to_string(),
                    ));
                } else {
                    let last = self.machines.len() - 1;
                    self.machines[last].password = Some(name)
                }
                Ok(())
            }

            Token::Account => {
                let name = lexer.next_token()?.to_string();
                count.account += 1;
                if count.account > count.machine {
                    return Err(Error::IllegalFormat(
                        lexer.tokens.position(),
                        "account must follow machine".to_string(),
                    ));
                } else {
                    let last = self.machines.len() - 1;
                    self.machines[last].account = Some(name)
                }
                Ok(())
            }

            // Just skip to end of macdefs
            Token::MacDef => {
                let name = lexer.next_token()?.to_string();
                let cmds = lexer.next_commands();

                self.macdefs.push((name, cmds));
                Ok(())
            }

            Token::Str(s) if unknown_entries => {
                self.unknown_entries.push(s.to_string());
                Ok(())
            }

            Token::Str(s) => Err(Error::IllegalFormat(
                lexer.tokens.position(),
                format!("token: {}", s),
            )),
        }
    }
}

#[derive(Debug, Default)]
struct MachineCount {
    machine: usize,
    login: usize,
    password: usize,
    account: usize,
}

#[derive(Debug)]
enum Token {
    Machine,
    Default,
    Login,
    Password,
    Account,
    MacDef,
    Str(String),
}

impl Display for Token {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use Token::*;

        let s = match self {
            Machine => "machine",
            Default => "default",
            Login => "login",
            Password => "password",
            Account => "account",
            MacDef => "macdef",
            Str(s) => s,
        };

        write!(f, "{}", s)
    }
}

impl Token {
    fn new(s: String) -> Self {
        use Token::*;

        match s.as_str() {
            "machine" => Machine,
            "default" => Default,
            "login" => Login,
            "password" => Password,
            "account" => Account,
            "macdef" => MacDef,

            _ => Str(s),
        }
    }
}

struct Tokens<'a> {
    buf: Chars<'a>,
    pos: Position,
}

impl Display for Position {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.0, self.1)
    }
}

impl<'a> Tokens<'a> {
    fn new<T: AsRef<str>>(buf: &'a T) -> Self {
        Self {
            buf: buf.as_ref().chars(),
            pos: Position(1, 1),
        }
    }

    fn update_position(&mut self, ch: char) {
        if ch == '\n' {
            self.pos.0 += 1;
            self.pos.1 = 1;
        } else {
            self.pos.1 += 1;
        }
    }

    fn position(&self) -> Position {
        self.pos
    }

    fn skip_whitespace(&mut self) {
        for ch in self.buf.clone() {
            if !ch.is_whitespace() {
                break;
            }

            self.update_position(ch);
            self.buf.next();
        }
    }

    fn next_token(&mut self) -> Option<Token> {
        self.skip_whitespace();
        if self.buf.clone().next().is_some() {
            let mut s = String::new();
            for ch in self.buf.clone() {
                if ch.is_whitespace() {
                    break;
                }

                self.update_position(ch);
                self.buf.next();
                s.push(ch);
            }

            if s.is_empty() {
                None
            } else {
                Some(Token::new(s))
            }
        } else {
            None
        }
    }

    fn next_commands(&mut self) -> Vec<String> {
        self.skip_whitespace();
        let mut cmds = vec![];
        for line in self.buf.clone().as_str().lines() {
            for _ in 0..=line.len() {
                self.buf.next();
            }
            if line.is_empty() || line == "\n" {
                break;
            }
            cmds.push(line.trim().to_string());
        }
        self.pos.0 += cmds.len();
        self.pos.1 = 1;
        cmds
    }
}

struct Lexer<'a> {
    tokens: Tokens<'a>,
}

impl<'a> Lexer<'a> {
    fn new<T: AsRef<str>>(buf: &'a T) -> Self {
        Self {
            tokens: Tokens::new(buf),
        }
    }

    fn next_token(&mut self) -> Result<Token> {
        self.tokens.next_token().ok_or(Error::EOF)
    }

    fn next_commands(&mut self) -> Vec<String> {
        self.tokens.next_commands()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_token() {
        let input = r#"
machine host1.com login login1
macdef test
cd /pub/tests
bin
put filename.tar.gz
quit
machine host2.com login login2"#
            .to_string();
        let mut tokens = Tokens::new(&input);
        let strs: Vec<&str> = input.split_whitespace().collect();
        let mut count = 0;
        loop {
            match tokens.next_token() {
                Some(tok) => {
                    assert_eq!(tok.to_string().as_str(), strs[count]);
                    count += 1;
                }
                None => break,
            }
        }
    }

    #[test]
    fn parse_simple() {
        let input = "machine 中文.com login test password p@ssw0rd".to_string();
        let netrc = Netrc::parse(input, false).unwrap();
        assert_eq!(netrc.machines.len(), 1);
        assert!(netrc.macdefs.is_empty());
        let machine = netrc.machines[0].clone();
        assert_eq!(machine.name, Some("中文.com".into()));
        assert_eq!(machine.login, Some("test".into()));
        assert_eq!(machine.password.as_ref().unwrap(), "p@ssw0rd");
        assert_eq!(machine.account, None);
    }

    #[test]
    fn parse_unknown() {
        let input = "machine example.com login test my_entry1 password foo my_entry2".to_string();
        let netrc = Netrc::parse(input, true).unwrap();
        assert_eq!(netrc.machines.len(), 1);
        assert!(netrc.macdefs.is_empty());
        assert_eq!(
            netrc.unknown_entries,
            vec!["my_entry1".to_string(), "my_entry2".to_string()]
        );

        let machine = netrc.machines[0].clone();
        assert_eq!(machine.name, Some("example.com".into()));
        assert_eq!(machine.login, Some("test".into()));
        assert_eq!(machine.password.as_ref().unwrap(), "foo");
    }

    #[test]
    fn parse_macdef() {
        let input = r#"machine host0.com login login0
                     macdef uploadtest
                            cd /pub/tests
                            bin
                            put filename.tar.gz
                            echo 中文测试
                            quit

                     machine host1.com login login1"#;
        let netrc = Netrc::parse(input, false).unwrap();
        assert_eq!(netrc.machines.len(), 2);
        for (i, machine) in netrc.machines.iter().enumerate() {
            assert_eq!(machine.name, Some(format!("host{}.com", i)));
            assert_eq!(machine.login, Some(format!("login{}", i)));
        }
        assert_eq!(netrc.macdefs.len(), 1);
        let (ref name, ref cmds) = netrc.macdefs[0];
        assert_eq!(name, "uploadtest");
        assert_eq!(
            *cmds,
            vec![
                "cd /pub/tests",
                "bin",
                "put filename.tar.gz",
                "echo 中文测试",
                "quit"
            ]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<String>>()
        )
    }

    #[test]
    fn parse_default() {
        let input = r#"machine example.com login test
            default login def"#;
        let netrc = Netrc::parse(input, false).unwrap();
        assert_eq!(netrc.machines.len(), 2);

        let machine = netrc.machines[0].clone();
        assert_eq!(machine.name, Some("example.com".into()));
        assert_eq!(machine.login, Some("test".into()));

        let machine = netrc.machines[1].clone();
        assert_eq!(machine.name, None);
        assert_eq!(machine.login, Some("def".into()));
    }

    #[test]
    fn parse_error_unknown_entry() {
        let input = "machine foobar.com foo";
        match Netrc::parse(input, false).unwrap_err() {
            Error::IllegalFormat(_pos, _s) => {}
            e => panic!("Error type: {:?}", e),
        }
    }

    #[test]
    fn parse_error_eof() {
        let input = "machine foobar.com password melody login";
        match Netrc::parse(input, false).unwrap_err() {
            Error::EOF => {}
            e => panic!("Error type: {}", e),
        }
    }

    #[test]
    fn parse_error_illegal_format() {
        let input = "password bar login foo";
        match Netrc::parse(input, false).unwrap_err() {
            Error::IllegalFormat(_pos, _s) => {}
            e => panic!("Error type: {}", e),
        }
    }
}
