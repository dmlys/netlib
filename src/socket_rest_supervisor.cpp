// author: Dmitry Lysachenko
// date: Saturday 19 march 2017
// license: boost software license
//          http://www.boost.org/LICENSE_1_0.txt

#include <ext/netlib/socket_rest_supervisor.hpp>
#include <boost/scope_exit.hpp>

#include <ext/Errors.hpp>
#include <ext/library_logger/logging_macros.hpp>

namespace ext {
namespace netlib
{
	namespace
	{
		template <class lock>
		class reverse_lock
		{
		private:
			lock & m_lk;

		public:
			explicit reverse_lock(lock & lk) noexcept : m_lk(lk) { lk.unlock(); }
			~reverse_lock() noexcept { m_lk.lock(); }

			reverse_lock(reverse_lock &&) = delete;
			reverse_lock && operator =(reverse_lock &&) = delete;
		};
	}


	/************************************************************************/
	/*                  Connect/Disconnect                                  */
	/************************************************************************/
	void socket_rest_supervisor::do_connect_request(unique_lock lk)
	{
		assert(lk.owns_lock());
		assert(not m_connect_request);

		m_connect_request = true;

		// start thread if not started yet,
		// once started thread works until this object is destroyed
		if (not m_thread.joinable())
		{
			m_thread_state = running;
			m_thread = std::thread(&socket_rest_supervisor::thread_proc, this);
		}

		lk.unlock();
		m_request_event.notify_all();
	}

	void socket_rest_supervisor::do_disconnect_request(unique_lock lk)
	{
		assert(lk.owns_lock());
		assert(not m_disconnect_request);

		m_disconnect_request = true;
		//m_sockstream.interrupt();

		lk.unlock();
		m_request_event.notify_all();
	}

	auto socket_rest_supervisor::wait_request(std::string & host, std::string & service, std::chrono::steady_clock::duration & timeout)
		-> thread_state
	{
		unique_lock lk(m_mutex);

		while (m_thread_state == running)
		{
			auto waiter = [this] { return m_connect_request or m_thread_state == stopped; };
			m_request_event.wait(lk, waiter);

			// m_disconnect_request will be set only if was connect request immediately followed by disconnect
			if (not m_disconnect_request) break;

			// skip connect attempt, but notify about disconnect
			assert(m_connect_request);
			m_disconnect_request = m_connect_request = false;
			notify_disconnected(std::move(lk));
			lk = unique_lock(m_mutex);
		};

		m_connect_request = false; // request taken
		m_sockstream.reset();

		host = m_host;
		service = m_service;
		timeout = m_timeout;

		return m_thread_state;
	}

	bool socket_rest_supervisor::exec_connect(const std::string & host, const std::string & service, std::chrono::steady_clock::duration timeout)
	{
		EXTLL_INFO(m_logger, "Connecting to " << host << ":" << service);

		if (timeout.count() > 0) m_sockstream.timeout(timeout);
		m_sockstream.connect(host, service);

		if (not m_sockstream)
		{
			on_socket_error();
			return false;
		}
		else
		{
			EXTLL_INFO(m_logger, "Successfully connected to " << host << ":" << service);
			
			unique_lock lk(m_mutex);
			notify_connected(std::move(lk));
			return true;
		}
	}

	void socket_rest_supervisor::exec_disconnect()
	{
		m_sockstream.close();
		EXTLL_INFO(m_logger, "Disconnected");

		unique_lock lk(m_mutex);
		m_disconnect_request = false;

		notify_disconnected(std::move(lk));
	}

	void socket_rest_supervisor::on_conn_error(std::runtime_error & ex)
	{
		std::string errmsg;
		errmsg.reserve(1024);
		error_code_type ec = m_sockstream.last_error();

		errmsg = ex.what();
		errmsg += "; socket_state - ";
		errmsg += ext::FormatError(ec);

		EXTLL_ERROR(m_logger, errmsg);

		/// set error info
		unique_lock lk(m_mutex);
		m_disconnect_request = false; // take off disconnect request if any
		m_lasterr = ec;
		m_lasterr_message = std::move(errmsg);
		m_sockstream.close();

		notify_disconnected(std::move(lk));
	}

	void socket_rest_supervisor::on_socket_error()
	{
		std::string errmsg = "socket_stream error. ";
		errmsg += ext::FormatError(m_sockstream.last_error());

		EXTLL_ERROR(m_logger, errmsg);

		/// set error
		unique_lock lk(m_mutex);
		m_disconnect_request = false; // take off disconnect request if any
		m_lasterr = m_sockstream.last_error();
		m_lasterr_message = std::move(errmsg);
		m_sockstream.close();

		notify_disconnected(std::move(lk));
	}

	std::string socket_rest_supervisor::last_errormsg()
	{
		unique_lock lk(m_mutex);
		return m_lasterr_message;
	}

	auto socket_rest_supervisor::last_error() -> error_code_type
	{
		unique_lock lk(m_mutex);
		return m_lasterr;
	}

	void socket_rest_supervisor::set_address(std::string host, std::string service)
	{
		unique_lock lk(m_mutex);
		m_host = host;
		m_service = service;
	}

	void socket_rest_supervisor::set_timeout(std::chrono::steady_clock::duration timeout)
	{
		unique_lock lk(m_mutex);
		m_timeout = timeout;
	}

	void socket_rest_supervisor::set_request_slots(unsigned nslots)
	{
		if (nslots == 0) nslots = 1;
		m_request_slots.store(nslots, std::memory_order_relaxed);
	}

	void socket_rest_supervisor::set_logger(ext::library_logger::logger * logger)
	{
		m_logger = logger;
	}

	/************************************************************************/
	/*                     Action management                                */
	/************************************************************************/
	void socket_rest_supervisor::run_subscriptions()
	{
		unsigned request_slots = m_request_slots.load(std::memory_order_relaxed);
		std::chrono::steady_clock::time_point next_reschedule;
		
		item_list requests, replies;
		item_list & waiting = m_items;

		BOOST_SCOPE_EXIT_ALL(&waiting, &requests, &replies)
		{
			waiting.splice(waiting.end(), requests);
			waiting.splice(waiting.end(), replies);
		};

		unique_lock lk(m_mutex);
		for (;;)
		{
			// disconnect request
			// flag is reset in exec_disconnect, which is called from thread_proc
			if (m_disconnect_request) break;
			
			if (requests.empty())
			{
				// no pending requests, we should try reschedule
				next_reschedule = schedule_subscriptions(lk, waiting, requests);
				if (not requests.empty()) goto request_avail;
			}
			else request_avail:
			{
				// take one subscription, make request, place it into replies
				replies.splice(replies.end(), requests, requests.begin());
				auto & task = replies.back();
				bool made = task.make_request(lk, m_sockstream);
				
				if (request_slots -= made) continue;
				else                       goto reply_avail;
			}
			
			if (replies.empty())
			{
				// check if we should disconnected
				if (m_disconnect_request) break;
				// both replies and requests are empty, wait for next_reschedule and repeat cycle
				assert(requests.empty());
				m_request_event.wait_until(lk, next_reschedule);
				continue;
			}
			else reply_avail:
			{
				// take pending reply subscription, process response, place it back into waiting
				++request_slots;
				waiting.splice(waiting.end(), replies, replies.begin());
				auto & task = waiting.back();
				task.process_response(lk, m_sockstream);
			}
		}
	}

	auto socket_rest_supervisor::schedule_subscriptions(unique_lock & lk, item_list & waiting, item_list & requests)
		-> std::chrono::steady_clock::time_point
	{
		assert(lk.owns_lock());

		item_list subs, result;
		auto next_reschedule = max_timepoint();

		do {
			subs.splice(subs.end(), waiting);
			reverse_lock<unique_lock> rlk(lk);

			auto now = std::chrono::steady_clock::now();
			auto first = subs.begin();
			auto last = subs.end();

			while (first != last)
			{
				if (first->is_paused())
				{
					++first;
					continue;
				}

				auto invoke = first->next_invoke();
				if (invoke > now)
					next_reschedule = std::min(next_reschedule, invoke), ++first;
				else
					result.splice(result.end(), subs, first++);
			}

		} while (not waiting.empty());

		waiting.splice(waiting.end(), subs);

		if (result.empty())
			return next_reschedule;
		
		requests.splice(requests.end(), result);
		return std::chrono::steady_clock::now();
	}

	void socket_rest_supervisor::thread_proc()
	{
		for (;;)
		{
			std::string host, service;
			std::chrono::steady_clock::duration timeout;

			auto state = wait_request(host, service, timeout);
			if (state == stopped) return;

			try 
			{
				if (exec_connect(host, service, timeout))
				{
					run_subscriptions();
					exec_disconnect();
				}
			}
			catch (std::runtime_error & ex)
			{
				on_conn_error(ex);
			}
		}
	}

	void socket_rest_supervisor::add_item(item * ptr)
	{
		assert(ptr);
		unique_lock lk(m_mutex);

		ptr->m_owner = this;
		ptr->addref();

		m_items.push_back(*ptr);
	
		lk.unlock();
		m_request_event.notify_all();
	}

	socket_rest_supervisor::~socket_rest_supervisor() noexcept
	{
		m_thread_state = stopped;
		m_request_event.notify_all();
		disconnect();

		if (m_thread.joinable())
			m_thread.join();

		m_items.clear_and_dispose([](auto * ptr)
		{
			// add_subscrition calls addref - we have to release
			ptr->abandon();
			ptr->release();
		});
	}

	bool socket_rest_supervisor_request_base::make_request(parent_lock & srs_lk, ext::socket_stream & stream)
	{
		auto * state = get_shared_state();
		if (state and not state->mark_uncancellable())
		{
			// if already cancelled - do nothing, and release request
			unlink(); release(); return false;
		}

		try
		{
			reverse_lock<parent_lock> rlk(srs_lk);
			request(stream);
			return true;
		}
		catch (std::runtime_error & )
		{
			BOOST_SCOPE_EXIT_ALL(this)
			{
				unlink(); release();
			};

			if (not state) throw;
			state->set_exception(std::current_exception());
			if (not stream) throw;

			return false;
		}
	}

	void socket_rest_supervisor_request_base::process_response(parent_lock & srs_lk, ext::socket_stream & stream)
	{
		try
		{
			reverse_lock<parent_lock> rlk(srs_lk);
			response(stream);

			if (should_repeat())
				reset_repeat();
			else
			{
				unlink(); release();
			}
		}
		catch (std::runtime_error & )
		{
			BOOST_SCOPE_EXIT_ALL(this)
			{
				unlink(); release();
			};

			auto * state = get_shared_state();
			if (not state) throw;
			state->set_exception(std::current_exception());
			if (not stream) throw;
		}
	}

	auto socket_rest_supervisor_request_base::next_invoke() -> std::chrono::steady_clock::time_point
	{
		return std::chrono::steady_clock::time_point::min();
	}


	void socket_rest_supervisor_subscription::do_pause_request(unique_lock lk)
	{
		set_paused();
		notify_paused(std::move(lk));
	}

	void socket_rest_supervisor_subscription::do_resume_request(unique_lock lk)
	{
		auto owner = m_owner;
		reset_paused();
		notify_resumed(std::move(lk));

		if (owner) notify();
	}

	void socket_rest_supervisor_subscription::do_close_request(unique_lock lk)
	{
		if (is_orphan())
		{
			assert(not is_linked());
			notify_closed(std::move(lk));
			return;
		}

		{
			parent_lock srs_lk(parent_mutex());
			if (is_pending()) return;

			notify_closed(std::move(lk));
			unlink();
		}
		
		// add_subscrition calls addref - on close we have to release
		release();
	}

	bool socket_rest_supervisor_subscription::make_request(parent_lock & srs_lk, ext::socket_stream & stream)
	{
		bool success = false;
		set_pending();

		BOOST_SCOPE_EXIT_ALL(&)
		{
			unique_lock lk(m_mutex);
			if (not success and get_state(lk) > closing)
			{
				reset_pending();
				notify_closed(std::move(lk));
				unlink(); release();
			}
		};

		{
			reverse_lock<parent_lock> rlk(srs_lk);
			request(stream);
		}

		check_stream(stream);
		success = true;
		return true;
	}

	void socket_rest_supervisor_subscription::process_response(parent_lock & srs_lk, ext::socket_stream & stream)
	{
		BOOST_SCOPE_EXIT_ALL(&)
		{
			reset_pending();

			// we got close request, while between request and response
			unique_lock lk(m_mutex);
			if (get_state(lk) >= closing)
			{
				notify_closed(std::move(lk));
				unlink(); release();
			}
		};

		{
			reverse_lock<parent_lock> rlk(srs_lk);
			response(stream);
		}

		check_stream(stream);
	}
}}
