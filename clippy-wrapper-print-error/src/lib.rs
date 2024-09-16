#![feature(internal_output_capture)]
use capture_stdio::Capture;
use std::io::BufRead;
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref PRINT_ERROR_LOCK: Mutex<()> = Mutex::new(());
}

pub fn print_error<F: FnOnce()>(cb: F) {
    let _lock = PRINT_ERROR_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let port = std::env::var("SCOUT_PORT_NUMBER");

    if port.is_err() {
        cb();
        return;
    }

    let pipe_result = capture_stdio::PipedStderr::capture();
    if pipe_result.is_err() {
        cb();
        return;
    }

    let old = std::io::set_output_capture(None);
    let mut piped_stderr = pipe_result.unwrap();

    let port = port.unwrap();

    // Use catch_unwind to handle potential panics
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        cb();
    }));

    let _ = std::io::set_output_capture(old);
    let mut captured = String::new();
    let mut buf_reader = std::io::BufReader::new(piped_stderr.get_reader());
    let _ = buf_reader.read_line(&mut captured);

    let krate = std::env::var("CARGO_CRATE_NAME");
    let krate = krate.unwrap_or_default();

    let body = {
        let json = serde_json::from_str::<serde_json::Value>(&captured);
        if let Ok(json) = json {
            serde_json::json!({
                "crate": krate,
                "message": json,
            })
            .to_string()
        } else {
            captured
        }
    };

    let _ = reqwest::blocking::Client::new()
        .post(format!("http://127.0.0.1:{port}/vuln"))
        .body(body)
        .send();

    // Re-panic if the callback panicked
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
