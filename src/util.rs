pub(crate) const VAR_INT_BUF_SIZE: usize = 5;

pub(crate) fn get_sized_buf(buf: &mut Option<Vec<u8>>, offset: usize, size: usize) -> &mut [u8] {
    let end_at = offset + size;
    loop {
        match buf {
            Some(v) => {
                ensure_buf_has_size(v, end_at);
                break &mut v[offset..end_at];
            }
            None => {
                let new_buf = Vec::with_capacity(end_at);
                *buf = Some(new_buf);
            }
        }
    }
}
fn ensure_buf_has_size(buf: &mut Vec<u8>, total_size: usize) {
    let cur_len = buf.len();
    if cur_len >= total_size {
        return;
    }

    let additional = total_size - cur_len;
    buf.reserve(additional);
    unsafe {
        let start_at = buf.as_mut_ptr();
        let start_write_at = start_at.offset(cur_len as isize);
        std::ptr::write_bytes(start_write_at, 0, additional);
        buf.set_len(total_size);
    }
}

pub(crate) fn move_data_rightwards(target: &mut [u8], size: usize, shift_amount: usize) {
    let required_len = size + shift_amount;
    let actual_len = target.len();
    if actual_len < required_len {
        panic!(
            "move of data to the right (0..{} -> {}..{}) exceeds size of buffer {}",
            size, shift_amount, required_len, actual_len,
        )
    }

    unsafe { move_data_rightwards_unchecked(target, size, shift_amount) }
}

unsafe fn move_data_rightwards_unchecked(target: &mut [u8], size: usize, shift_amount: usize) {
    if shift_amount == 0 {
        return;
    }

    let src_ptr = target.as_mut_ptr();
    let dst_ptr = src_ptr.offset(shift_amount as isize);
    std::ptr::copy(src_ptr, dst_ptr, size);
}
