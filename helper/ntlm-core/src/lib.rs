use ntlm_hash::*;
#[no_mangle]
pub extern "C" fn gen(data: *const std::os::raw::c_char) -> *const std::os::raw::c_char {
    let d = unsafe { std::ffi::CStr::from_ptr(data).to_str().unwrap() };
    let hash = ntlm_hash(d);
    std::ffi::CString::new(hash).unwrap().into_raw()
}
