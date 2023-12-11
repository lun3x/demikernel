// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::runtime::{
    fail::Fail,
    scheduler::{
        Yielder,
        YielderHandle,
    },
    SharedObject,
};
use ::std::{
    collections::{
        vec_deque::{
            Iter,
            IterMut,
        },
        VecDeque,
    },
    ops::{
        Deref,
        DerefMut,
    },
    vec::Vec,
};

//======================================================================================================================
// Structures
//======================================================================================================================

/// This data structure implements an unbounded asynchronous queue that is hooked into the Demikernel scheduler. On
/// pop, if the queue is empty, the coroutine will yield until there is data to be read.
pub struct AsyncQueue<T> {
    queue: VecDeque<T>,
    waiters: Vec<YielderHandle>,
}

#[derive(Clone)]
pub struct SharedAsyncQueue<T>(SharedObject<AsyncQueue<T>>);

//======================================================================================================================
// Associate Functions
//======================================================================================================================

impl<T> AsyncQueue<T> {
    /// This function allocates a shared async queue with a specified capacity.
    // TODO: Enforce capacity limit and do not let queue grow past that.
    pub fn with_capacity(size: usize) -> Self {
        Self {
            queue: VecDeque::<T>::with_capacity(size),
            waiters: Vec::<YielderHandle>::new(),
        }
    }

    /// Push to a async queue. Currently async queues are unbounded, so we can synchronously push to them but we will
    /// add bounds checking in the future.
    pub fn push(&mut self, item: T) {
        self.queue.push_back(item);
        if let Some(mut handle) = self.waiters.pop() {
            handle.wake_with(Ok(()));
        }
    }

    pub fn push_front(&mut self, item: T) {
        self.queue.push_front(item);
        if let Some(mut handle) = self.waiters.pop() {
            handle.wake_with(Ok(()));
        }
    }

    /// Pop from an async queue. If the queue is empty, this function blocks until it finds something in the queue.
    pub async fn pop(&mut self, yielder: &Yielder) -> Result<T, Fail> {
        match self.queue.pop_front() {
            Some(item) => Ok(item),
            None => {
                let handle: YielderHandle = yielder.get_handle();
                self.waiters.push(handle);
                match yielder.yield_until_wake().await {
                    Ok(()) => match self.queue.pop_front() {
                        Some(item) => Ok(item),
                        None => {
                            let cause: &str = "Spurious wake up!";
                            warn!("pop(): {}", cause);
                            Err(Fail::new(libc::EAGAIN, cause))
                        },
                    },
                    Err(e) => Err(e),
                }
            },
        }
    }

    /// Try to get the head of the queue.
    pub fn try_pop(&mut self) -> Option<T> {
        self.queue.pop_front()
    }

    /// Get the length of the queue.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Check if the queue is empty.
    #[allow(unused)]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Get an iterator over values
    #[allow(unused)]
    pub fn get_values(&self) -> Iter<T> {
        self.queue.iter()
    }

    /// Get an iterator over mutable values
    pub fn get_mut_values(&mut self) -> IterMut<T> {
        self.queue.iter_mut()
    }
}

impl<T> SharedAsyncQueue<T> {
    /// This function allocates a shared async queue with a specified capacity.
    // TODO: Enforce capacity limit and do not let queue grow past that.
    #[allow(dead_code)]
    pub fn with_capacity(size: usize) -> Self {
        Self(SharedObject::<AsyncQueue<T>>::new(AsyncQueue::with_capacity(size)))
    }
}

//======================================================================================================================
// Trait Implementations
//======================================================================================================================

impl<T> Default for AsyncQueue<T> {
    fn default() -> Self {
        Self {
            queue: VecDeque::<T>::new(),
            waiters: Vec::<YielderHandle>::new(),
        }
    }
}
impl<T> Default for SharedAsyncQueue<T> {
    fn default() -> Self {
        Self(SharedObject::new(AsyncQueue::default()))
    }
}

impl<T> Deref for SharedAsyncQueue<T> {
    type Target = AsyncQueue<T>;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl<T> DerefMut for SharedAsyncQueue<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}
