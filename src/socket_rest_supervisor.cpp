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

		if (timeout.count()) m_sockstream.timeout(timeout);
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
		error_code_type ec;
		errmsg.reserve(1024);

		if (auto se = dynamic_cast<ext::socket_stream::system_error_type *>(&ex))
		{
			ec = se->code();
			errmsg = "socket_stream error. ";
			errmsg += ext::FormatError(ec);
		}
		else
		{
			ec = std::io_errc::stream;
			errmsg = ex.what();
			if (m_sockstream.last_error())
			{
				ec = m_sockstream.last_error();
				errmsg += "; socket_stream state - ";
				errmsg += ext::FormatError(ec);
			}
		}

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

	void socket_rest_supervisor::set_timeout(std::chrono::system_clock::duration timeout)
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
		
		subscription_list requests, replies;
		subscription_list & waiting = m_subscriptions;

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
				task.make_request(lk, m_sockstream);
				
				if (--request_slots) continue;
				else                 goto reply_avail;
			}
			
			if (replies.empty())
			{
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

		BOOST_SCOPE_EXIT_ALL(&waiting, &requests, &replies)
		{
			waiting.splice(waiting.end(), requests);
			waiting.splice(waiting.end(), replies);
		};
	}

	auto socket_rest_supervisor::schedule_subscriptions(unique_lock & lk, subscription_list & waiting, subscription_list & requests)
		-> std::chrono::steady_clock::time_point
	{
		assert(lk.owns_lock());

		subscription_list subs, result;
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

	subscription_handle socket_rest_supervisor::add_subscription(subscription_ptr sub)
	{
		unique_lock lk(m_mutex);

		sub->m_owner = this;
		sub.addref();

		m_subscriptions.push_back(*sub);
	
		lk.unlock();
		m_request_event.notify_all();
		return sub;
	}

	socket_rest_supervisor::~socket_rest_supervisor() noexcept
	{
		m_thread_state = stopped;
		m_request_event.notify_all();
		disconnect();
		m_thread.join();

		m_subscriptions.clear_and_dispose([](auto * ptr)
		{
			// add_subscrition calls addref - we have to release
			ext::intrusive_ptr_release(ptr);
		});
	}

	void socket_rest_supervisor_subscription::do_pause_request(unique_lock lk)
	{
		m_paused.exchange(true, std::memory_order_relaxed);
		notify_paused(std::move(lk));
	}

	void socket_rest_supervisor_subscription::do_resume_request(unique_lock lk)
	{
		auto owner = m_owner;
		m_paused.exchange(false, std::memory_order_relaxed);
		notify_resumed(std::move(lk));

		if (m_owner)
			m_owner->m_request_event.notify_all();
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
			parent_lock srs_lk(m_owner->m_mutex);
			if (m_pending.load(std::memory_order_relaxed)) return;

			notify_closed(std::move(lk));
			unlink();
		}
		
		// add_subscrition calls addref - on close we have to release
		ext::intrusive_ptr_release(this);
	}

	void socket_rest_supervisor_subscription::make_request(parent_lock & srs_lk, ext::socket_stream & stream)
	{
		bool success = false;
		m_pending.store(true, std::memory_order_relaxed);

		{
			reverse_lock<parent_lock> rlk(srs_lk);
			request(stream);
		}

		check_stream(stream);
		success = true;

		BOOST_SCOPE_EXIT_ALL(&)
		{
			unique_lock lk(m_mutex);
			if (not success and get_state(lk) > closing)
			{
				m_pending.store(false, std::memory_order_relaxed);
				unlink();
				notify_closed(std::move(lk));
				ext::intrusive_ptr_release(this);
			}
		};
	}

	void socket_rest_supervisor_subscription::process_response(parent_lock & srs_lk, ext::socket_stream & stream)
	{
		{
			reverse_lock<parent_lock> rlk(srs_lk);
			response(stream);
		}

		check_stream(stream);

		BOOST_SCOPE_EXIT_ALL(&)
		{
			m_pending.store(false, std::memory_order_relaxed);

			// we got close request, while between request and response
			unique_lock lk(m_mutex);
			if (get_state(lk) >= closing)
			{
				unlink();
				notify_closed(std::move(lk));
				ext::intrusive_ptr_release(this);
			}
		};
	}

	void socket_rest_supervisor_request::make_request(parent_lock & srs_lk, ext::socket_stream & stream)
	{
		bool success = false;
		m_pending.store(true, std::memory_order_relaxed);

		{
			reverse_lock<parent_lock> rlk(srs_lk);
			request(stream);
		}

		check_stream(stream);
		success = true;

		BOOST_SCOPE_EXIT_ALL(&)
		{
			unique_lock lk(m_mutex);
			if (not success)
			{
				m_pending.store(false, std::memory_order_relaxed);
				unlink();
				notify_closed(std::move(lk));
				ext::intrusive_ptr_release(this);
			}
		};
	}

	void socket_rest_supervisor_request::process_response(parent_lock & srs_lk, ext::socket_stream & stream)
	{
		{
			reverse_lock<parent_lock> rlk(srs_lk);
			response(stream);
		}

		check_stream(stream);

		BOOST_SCOPE_EXIT_ALL(&)
		{
			m_pending.store(false, std::memory_order_relaxed);

			// we got close request, while between request and response
			unique_lock lk(m_mutex);
			unlink();
			notify_closed(std::move(lk));
			ext::intrusive_ptr_release(this);
		};
	}

	auto socket_rest_supervisor_request::next_invoke() -> std::chrono::steady_clock::time_point
	{
		return std::chrono::steady_clock::time_point::min();
	}
}}
