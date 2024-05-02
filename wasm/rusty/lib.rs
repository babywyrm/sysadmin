// src/lib.rs

use wasm_bindgen::prelude::*;

// Define a function to evaluate JavaScript code
#[wasm_bindgen]
pub fn evaluate_javascript_code(js_code: &str) -> String {
    // Use the `wasm-bindgen` `js_sys` module to call JavaScript functions
    // Evaluate the JavaScript code and return the result as a string
    match js_sys::eval(js_code) {
        Ok(value) => {
            if let Some(value) = value.as_string() {
                value
            } else {
                "Evaluation result is not a string".to_string()
            }
        }
        Err(e) => format!("Error: {}", e),
    }
}

//
