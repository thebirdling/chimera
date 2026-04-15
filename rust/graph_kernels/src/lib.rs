use std::collections::{HashMap, HashSet};
use std::slice;

#[no_mangle]
pub extern "C" fn shared_pair_prior_counts(
    pair_codes_ptr: *const i64,
    user_codes_ptr: *const i64,
    len: usize,
    out_ptr: *mut i64,
) {
    if pair_codes_ptr.is_null() || user_codes_ptr.is_null() || out_ptr.is_null() {
        return;
    }

    let pair_codes = unsafe { slice::from_raw_parts(pair_codes_ptr, len) };
    let user_codes = unsafe { slice::from_raw_parts(user_codes_ptr, len) };
    let out = unsafe { slice::from_raw_parts_mut(out_ptr, len) };

    let mut seen: HashMap<i64, HashSet<i64>> = HashMap::new();
    for idx in 0..len {
        let pair_code = pair_codes[idx];
        let user_code = user_codes[idx];
        let users = seen.entry(pair_code).or_insert_with(HashSet::new);
        out[idx] = users.len() as i64;
        users.insert(user_code);
    }
}

#[no_mangle]
pub extern "C" fn shared_pair_recent_peer_counts(
    pair_codes_ptr: *const i64,
    user_codes_ptr: *const i64,
    timestamps_ptr: *const i64,
    len: usize,
    window_seconds: i64,
    out_ptr: *mut i64,
) {
    if pair_codes_ptr.is_null()
        || user_codes_ptr.is_null()
        || timestamps_ptr.is_null()
        || out_ptr.is_null()
    {
        return;
    }

    let pair_codes = unsafe { slice::from_raw_parts(pair_codes_ptr, len) };
    let user_codes = unsafe { slice::from_raw_parts(user_codes_ptr, len) };
    let timestamps = unsafe { slice::from_raw_parts(timestamps_ptr, len) };
    let out = unsafe { slice::from_raw_parts_mut(out_ptr, len) };

    let mut left: usize = 0;
    let mut active: HashMap<i64, HashMap<i64, i64>> = HashMap::new();

    for idx in 0..len {
        let current_ts = timestamps[idx];
        while left < idx && current_ts - timestamps[left] > window_seconds {
            let expired_pair = pair_codes[left];
            let expired_user = user_codes[left];
            let mut remove_pair = false;

            if let Some(user_counts) = active.get_mut(&expired_pair) {
                let remaining = user_counts.get(&expired_user).copied().unwrap_or(0) - 1;
                if remaining > 0 {
                    user_counts.insert(expired_user, remaining);
                } else {
                    user_counts.remove(&expired_user);
                }
                if user_counts.is_empty() {
                    remove_pair = true;
                }
            }

            if remove_pair {
                active.remove(&expired_pair);
            }
            left += 1;
        }

        let current_pair = pair_codes[idx];
        let current_user = user_codes[idx];
        if let Some(user_counts) = active.get(&current_pair) {
            let self_present = if user_counts.contains_key(&current_user) { 1 } else { 0 };
            out[idx] = (user_counts.len() as i64 - self_present).max(0);
        } else {
            out[idx] = 0;
        }

        let user_counts = active.entry(current_pair).or_insert_with(HashMap::new);
        let count = user_counts.get(&current_user).copied().unwrap_or(0) + 1;
        user_counts.insert(current_user, count);
    }
}

#[no_mangle]
pub extern "C" fn ordered_takeover_sequence_progress(
    user_codes_ptr: *const i64,
    stage_codes_ptr: *const i64,
    timestamps_ptr: *const i64,
    len: usize,
    window_seconds: i64,
    out_ptr: *mut i64,
) {
    if user_codes_ptr.is_null()
        || stage_codes_ptr.is_null()
        || timestamps_ptr.is_null()
        || out_ptr.is_null()
    {
        return;
    }

    let user_codes = unsafe { slice::from_raw_parts(user_codes_ptr, len) };
    let stage_codes = unsafe { slice::from_raw_parts(stage_codes_ptr, len) };
    let timestamps = unsafe { slice::from_raw_parts(timestamps_ptr, len) };
    let out = unsafe { slice::from_raw_parts_mut(out_ptr, len) };

    let mut stage1_ts: HashMap<i64, i64> = HashMap::new();
    let mut stage2_ts: HashMap<i64, i64> = HashMap::new();

    for idx in 0..len {
        let user_code = user_codes[idx];
        let stage_code = stage_codes[idx];
        let ts = timestamps[idx];
        out[idx] = 0;

        match stage_code {
            1 => {
                stage1_ts.insert(user_code, ts);
                stage2_ts.remove(&user_code);
            }
            2 => {
                if let Some(&prior_stage1) = stage1_ts.get(&user_code) {
                    if ts - prior_stage1 <= window_seconds {
                        out[idx] = 1;
                        stage2_ts.insert(user_code, ts);
                    } else {
                        stage2_ts.remove(&user_code);
                    }
                }
            }
            3 => {
                if let (Some(&prior_stage1), Some(&prior_stage2)) =
                    (stage1_ts.get(&user_code), stage2_ts.get(&user_code))
                {
                    if prior_stage2 >= prior_stage1
                        && ts - prior_stage2 <= window_seconds
                        && ts - prior_stage1 <= window_seconds
                    {
                        out[idx] = 2;
                    }
                }
            }
            _ => {}
        }
    }
}
