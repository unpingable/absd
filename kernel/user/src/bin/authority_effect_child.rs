//! Valid child image for refused partial-copy cleanup; no service policy.
#![no_std]
#![no_main]
use absd_user::MultiStart;
absd_user::multi_entry!(main);
fn main(_start: MultiStart<'_>) -> i32 {
    0
}
