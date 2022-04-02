//! This module implements a thread pool with a number of threads returned from std::thread::available_parallelism if Some, or if None, then 4

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

type Task = Box<dyn FnOnceBox + Send + 'static>;

enum Message {
	NewTask(Task),
	Terminate
}

struct Worker {
	thread: Option<thread::JoinHandle<()>>
}

impl Worker {
	fn new(reciever: Arc<Mutex<mpsc::Receiver<Message>>>, await_condvar: Arc<(Condvar, Mutex<()>)>, num_tasks: Arc<AtomicUsize>) -> Self {
		Worker {
			thread: Some(thread::spawn(move || {
				loop {
					let message = reciever.lock().unwrap().recv().unwrap();

					num_tasks.fetch_sub(1, Ordering::SeqCst);
					await_condvar.0.notify_one();

					match message {
						Message::NewTask(taskptr) => {
							taskptr.call_once_box();
						},
						Message::Terminate => break
					}
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
	pub fn new() -> Self {
		let num_workers = match thread::available_parallelism() {
			Ok(n) => n.into(),
			Err(_) => 4
		};

		let (sender, reciever) = mpsc::channel();

		// Protect the reciever for using across threads
		let reciever = Arc::new(Mutex::new(reciever));

		let mut workers = Vec::with_capacity(num_workers);

		// Use an atomic usize for keeping track of number of tasks
		let num_tasks = Arc::new(AtomicUsize::new(0));
		let await_condvar = Arc::new((Condvar::new(), Mutex::new(())));

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

	pub fn assign_task<F>(&self, function: F) where F: FnOnce() + Send + 'static {
		let message = Message::NewTask(Box::new(function));
		self.sender.send(message).unwrap();
		self.num_tasks.fetch_add(1, Ordering::SeqCst);
	}

	pub fn await_all(&self) {
		// Wait until the number of tasks left is 0
		let _ = self.await_condvar.0.wait_while(self.await_condvar.1.lock().unwrap(), |_| {
			// Return whether the number of tasks left is greater than 0; If so then continue to wait
			self.num_tasks.load(Ordering::SeqCst) > 0
		}).unwrap();
	}
}

impl Drop for ThreadPool {
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