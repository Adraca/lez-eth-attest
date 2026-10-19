//! Entrypoint binary for the LEZ v0.3 on-chain guest program.

#[no_mangle]
pub unsafe extern "C" fn __atomic_load_4(ptr: *const u32, _model: i32) -> u32 {
    core::ptr::read_volatile(ptr)
}

#[no_mangle]
pub unsafe extern "C" fn __atomic_fetch_add_4(ptr: *mut u32, val: u32, _model: i32) -> u32 {
    let old = core::ptr::read_volatile(ptr);
    core::ptr::write_volatile(ptr, old.wrapping_add(val));
    old
}

#[no_mangle]
pub unsafe extern "C" fn __atomic_fetch_sub_4(ptr: *mut u32, val: u32, _model: i32) -> u32 {
    let old = core::ptr::read_volatile(ptr);
    core::ptr::write_volatile(ptr, old.wrapping_sub(val));
    old
}

#[no_mangle]
pub unsafe extern "C" fn __atomic_compare_exchange_4(
    ptr: *mut u32,
    expected: *mut u32,
    desired: u32,
    _success: i32,
    _failure: i32,
) -> bool {
    let cur = core::ptr::read_volatile(ptr);
    let exp = core::ptr::read_volatile(expected);
    if cur == exp {
        core::ptr::write_volatile(ptr, desired);
        true
    } else {
        core::ptr::write_volatile(expected, cur);
        false
    }
}

fn main() {
    lee_core::program::run_program::<_, _, [u8], Vec<u8>>(
        attest_program::plan,
        attest_program::apply,
    );
}
