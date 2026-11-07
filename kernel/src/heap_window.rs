//! The heap window bounds `map` and `unmap` use for the calling process.
//!
//! Without the #115 `builder-class-heap` feature these expand to exactly the
//! expressions they replace (`heap_search_end(reserved)` and the constant
//! `USER_HEAP_END`), so the ordinary build's code is unchanged. With it, a
//! builder-class process (`absd_kernel::builder_class`) gets the class
//! window instead; every other process keeps the ordinary bounds.

#[cfg(not(feature = "builder-class-heap"))]
#[macro_export]
macro_rules! heap_search_end {
    ($index:expr, $pid:expr, $reserved:expr) => {
        absd_kernel::frame_geometry::heap_search_end($reserved)
    };
}

#[cfg(feature = "builder-class-heap")]
#[macro_export]
macro_rules! heap_search_end {
    ($index:expr, $pid:expr, $reserved:expr) => {
        $crate::builder_heap::window_end(
            $index,
            $pid,
            absd_kernel::frame_geometry::heap_search_end($reserved),
        )
    };
}

#[cfg(not(feature = "builder-class-heap"))]
#[macro_export]
macro_rules! heap_end {
    ($index:expr, $pid:expr) => {
        USER_HEAP_END
    };
}

#[cfg(feature = "builder-class-heap")]
#[macro_export]
macro_rules! heap_end {
    ($index:expr, $pid:expr) => {
        $crate::builder_heap::window_end($index, $pid, USER_HEAP_END)
    };
}
