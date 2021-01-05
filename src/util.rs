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
    if total_size > buf.len() {
        buf.resize(total_size, 0u8);
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

    target.copy_within(0..size, shift_amount);
}