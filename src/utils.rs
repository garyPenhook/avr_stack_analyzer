//! Utility functions for AVR Stack Analyzer

use std::io::{self, Write};
use serde_json::{Value, to_value};
use serde::Serialize;

#[allow(dead_code)]
pub fn pretty_print_json<T: Serialize>(data: &T) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    
    let json_value: Value = to_value(data).unwrap_or(Value::Null);
    print_json_value(&mut handle, &json_value, 0)?;
    writeln!(handle)?;
    
    Ok(())
}

#[allow(dead_code)]
fn print_json_value<W: Write>(writer: &mut W, value: &Value, indent: usize) -> io::Result<()> {
    let indent_str = "    ".repeat(indent);
    
    match value {
        Value::Null => write!(writer, "null"),
        Value::Bool(b) => {
            if *b {
                write!(writer, "\x1b[36mtrue\x1b[0m") // Cyan
            } else {
                write!(writer, "\x1b[36mfalse\x1b[0m") // Cyan
            }
        },
        Value::Number(n) => write!(writer, "\x1b[33m{}\x1b[0m", n), // Yellow
        Value::String(s) => write!(writer, "\x1b[32m\"{}\"\x1b[0m", s), // Green
        Value::Array(arr) => {
            if arr.is_empty() {
                write!(writer, "[]")
            } else {
                writeln!(writer, "[")?;
                for (i, item) in arr.iter().enumerate() {
                    write!(writer, "{}", indent_str.repeat(1))?;
                    print_json_value(writer, item, indent + 1)?;
                    if i < arr.len() - 1 {
                        writeln!(writer, ",")?;
                    } else {
                        writeln!(writer)?;
                    }
                }
                write!(writer, "{}]", indent_str)
            }
        },
        Value::Object(obj) => {
            if obj.is_empty() {
                write!(writer, "{{}}")
            } else {
                writeln!(writer, "{{")?;
                let keys: Vec<_> = obj.keys().collect();
                for (i, key) in keys.iter().enumerate() {
                    write!(writer, "{}\x1b[35m\"{}\"\x1b[0m: ", indent_str.repeat(1), key)?; // Magenta for keys
                    print_json_value(writer, &obj[*key], indent + 1)?;
                    if i < keys.len() - 1 {
                        writeln!(writer, ",")?;
                    } else {
                        writeln!(writer)?;
                    }
                }
                write!(writer, "{}}}", indent_str)
            }
        }
    }
}
