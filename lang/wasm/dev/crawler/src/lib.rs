//
//
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, Response, Window, RequestMode};

#[wasm_bindgen]
pub async fn fetch_data(url: &str) -> Result<JsValue, JsValue> {
    // Access the global `window` object
    let window: Window = web_sys::window().ok_or("no global `window` exists")?;

    // Create and configure the request
    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);

    // Create a new `Request` object
    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|_| JsValue::from_str("Failed to create request"))?;

    // Send the request and get the response
    let response = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|_| JsValue::from_str("Failed to fetch"))?;
    
    // Convert the response to the `Response` type
    let response: Response = response.dyn_into()
        .map_err(|_| JsValue::from_str("Failed to cast response"))?;

    // Convert the response body to JSON
    let json = JsFuture::from(response.json()?)
        .await
        .map_err(|_| JsValue::from_str("Failed to convert response to JSON"))?;
    Ok(json)
}
