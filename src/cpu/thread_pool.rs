//! This module implements a thread pool

use std::{sync::{mpsc, Arc, Mutex, atomic::{AtomicUsize, Ordering}, Condvar}, thread};

#[cfg(test)]
#[test]
fn test_thread_pool() {
	let tp = ThreadPool::new();

	let arr: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new((0..32).map(|_| 0).collect()));

	for i in 0..32 {
		let arr2 = Arc::clone(&arr);
		tp.assign_task(move || {
			arr2.lock().unwrap()[i] = 1;
		});
	}

	tp.await_all();
	assert_eq!((0..32).map(|_| 1).collect::<Vec<u8>>(), *arr.lock().unwrap());
}

// Calling Fn* trait objects isn't stabilised/doesn't work in stable rust. Have to use a wee workaround by defining a trait
trait FnOnceBox {
	fn call_once_box(self: Box<Self>);
}

// Define function call_once_box for generic type F that implements FnOnce
impl<F: FnOnce()> FnOnceBox for F {
	fn call_once_box(self: Box<F>) {
		(*self)();
	}
}

/// A trait type of a Box (unique pointer) around a function that needs to be called only once (using non-callable trait object workaround) and that is safe to copy/pass between threads and that lives as long as the entire program
type Task = Box<dyn FnOnceBox + Send + 'static>;

/// Message enum for passing to worker threads. 2 variants: NewTask and Terminate
enum Message {
	NewTask(Task),
	Terminate
}

/// Convenience wrapper around a thread
struct Worker {
	thread: Option<thread::JoinHandle<()>>
}

impl Worker {
	/// Creates a thread that waits for messages and acts appropriately upon reception of them. The thread also decrements `num_tasks` when a task is completed and notifies `await_condvar`'s Condvar
	fn new(reciever: Arc<Mutex<mpsc::Receiver<Message>>>, await_condvar: Arc<(Condvar, Mutex<()>)>, num_tasks: Arc<AtomicUsize>) -> Self {
		Worker {
			thread: Some(thread::spawn(move || {
				loop {
					// Recieve a message from the channel (blocking when there are none available)
					let message = reciever.lock().unwrap().recv().unwrap();

					match message {
						Message::NewTask(taskptr) => {
							taskptr.call_once_box();
						},
						Message::Terminate => break
					}

					// Decrement `num_tasks` and notify the condition variable
					num_tasks.fetch_sub(1, Ordering::SeqCst);
					await_condvar.0.notify_one();
				}
			}))
		}
	}
}

pub struct ThreadPool {
	workers: Vec<Worker>,
	sender: mpsc::Sender<Message>,
	num_tasks: Arc<AtomicUsize>,
	await_condvar: Arc<(Condvar, Mutex<()>)>
}

impl ThreadPool {
	/// Construct a ThreadPool with a number of worker threads equal to the return value of `std::thread::available_parallelism` if `Some`, or if `None`, then 4
	pub fn new() -> Self {
		let num_workers = match thread::available_parallelism() {
			Ok(n) => n.into(),
			Err(_) => 4
		};

		// Create a multiple producer single consumer channel
		let (sender, reciever) = mpsc::channel();

		// Protect the reciever for using across threads
		let reciever = Arc::new(Mutex::new(reciever));

		// Preallocate
		let mut workers = Vec::with_capacity(num_workers);

		// Use an atomic usize for keeping track of number of tasks
		let num_tasks = Arc::new(AtomicUsize::new(0));
		// Create a Condvar and an associated Mutex that will be used for the `await_all` function
		let await_condvar = Arc::new((Condvar::new(), Mutex::new(())));

		// Create the workers
		for _ in 0..num_workers {
			workers.push(Worker::new(Arc::clone(&reciever), Arc::clone(&await_condvar), Arc::clone(&num_tasks)));
		}

		ThreadPool {
			workers,
			sender,
			num_tasks,
			await_condvar
		}
	}

	/// Assign a task to the ThreadPool that will be executed by a thread at some indeterminate point in the future
	pub fn assign_task<F>(&self, function: F) where F: FnOnce() + Send + 'static {
		let message = Message::NewTask(Box::new(function));
		self.sender.send(message).unwrap();
		// Increment the assigned tasks counter
		self.num_tasks.fetch_add(1, Ordering::SeqCst);
	}

	/// Blocks until all currently assigned tasks are complete
	pub fn await_all(&self) {
		// Wait until the number of tasks left is 0
		let _ = self.await_condvar.0.wait_while(self.await_condvar.1.lock().unwrap(), |_| {
			// Return whether the number of tasks left is greater than 0; If so then continue to wait
			self.num_tasks.load(Ordering::SeqCst) > 0
		}).unwrap();
	}
}

impl Drop for ThreadPool {
	/// Define behaviour for when ThreadPool goes out of scope/is dropped - We want to shut down all threads gracefully
	fn drop(&mut self) {
		// Instruct all workers to finish
		for _ in 0..self.workers.len() {
			self.sender.send(Message::Terminate).unwrap();
		}

		// Wait for all workers to finish
		for worker in &mut self.workers {
			if let Some(thread) = worker.thread.take() {
				thread.join().unwrap();
			}
		}
	}
}