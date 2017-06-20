#pragma once
// author: Dmitry Lysachenko
// date: Saturday 19 march 2017
// license: boost software license
//          http://www.boost.org/LICENSE_1_0.txt

#include <memory>
#include <string>

#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>

#include <boost/intrusive/list.hpp>
#include <boost/intrusive/list_hook.hpp>

#include <ext/iostreams/socket_stream.hpp>
#include <ext/library_logger/logger.hpp>

#include <ext/netlib/abstract_connection_controller.hpp>
#include <ext/netlib/abstract_subscription_controller.hpp>
#include <ext/netlib/subscription_handle.hpp>

namespace ext {
namespace netlib
{
	class socket_rest_supervisor;
	class socket_rest_supervisor_item;
	class socket_rest_supervisor_subscription;
	class socket_rest_supervisor_request_base;

	template <class ReturnType, class RequestBase>
	class socket_rest_supervisor_request;
	
	/// Basic abstract item interface for socket_rest_supervisor(see below),
	/// logically it's a child class of socket_rest_supervisor.
	///
	/// Clients should use socket_rest_supervisor_subscription/socket_rest_supervisor_subscription
	class socket_rest_supervisor_item :
		public boost::intrusive::list_base_hook<
			boost::intrusive::link_mode<boost::intrusive::link_mode_type::auto_unlink>
		>
	{
	private:
		typedef socket_rest_supervisor_item      self_type;
		friend socket_rest_supervisor;

	protected:
		typedef boost::intrusive::list_base_hook<
			boost::intrusive::link_mode<boost::intrusive::link_mode_type::auto_unlink>
		> hook_type;

	protected:
		typedef std::unique_lock<std::mutex> parent_lock;
		socket_rest_supervisor * m_owner = nullptr;

		/// can it be non atomic?
		std::atomic_uint m_flags = ATOMIC_VAR_INIT(0);
		static constexpr unsigned Paused  = 1 << 0;

	protected:
		static constexpr auto max_timepoint();
		static void check_stream(ext::socket_stream & stream);

		void set_parent(socket_rest_supervisor * parent) noexcept { m_owner = parent; }
		bool is_orphan() const noexcept { return m_owner == nullptr; }

		/// all items can be paused, if so - they are not working(value next_invoke is ignored) until they are unparsed
		bool is_paused() const noexcept { return (m_flags.load(std::memory_order_relaxed) & Paused) != 0; }
		void set_paused() noexcept      { m_flags.fetch_or(Paused, std::memory_order_relaxed); }
		void reset_paused() noexcept    { m_flags.fetch_and(~Paused, std::memory_order_relaxed); }

		std::string & host() const noexcept;
		std::mutex & parent_mutex() const noexcept;
		void notify() const noexcept;
		auto logger() const noexcept -> ext::library_logger::logger *;

	public:
		/// refcount part, use_count is for intrusive_ptr
		virtual unsigned addref() noexcept = 0;
		virtual unsigned release() noexcept = 0;
		virtual unsigned use_count() const noexcept = 0;

		/// item is abandoned and forgotten by supervisor,
		/// typically called on supervisor destruction
		virtual void abandon() noexcept {}

	public:
		/// writes request into sock
		virtual void request(ext::socket_stream & stream) = 0;
		/// reads and processes response from socket
		virtual void response(ext::socket_stream & stream) = 0;

		/// Returns time for next scheduled invocation.
		/// Normally called after request call, not necessary after response.
		/// 
		/// Typical implementation can schedule next invocation immediately, 
		/// or, in case no new data - return some delay.
		/// 
		/// It's okay to return time_point::max after request, and correct time_point after response.
		/// In case you you next_invoke is changed some where after response - 
		/// call notify() this will wake up internal thread.
		virtual auto next_invoke() -> std::chrono::steady_clock::time_point = 0;

	public:
		/// for socket_rest_supervisor use, calls request method
		virtual bool make_request(parent_lock & srs_lk, ext::socket_stream & stream) = 0;
		/// for socket_rest_supervisor use, calls process method
		virtual void process_response(parent_lock & srs_lk, ext::socket_stream & stream) = 0;

	public:
		virtual ~socket_rest_supervisor_item() = default;
	};

	/// Abstract base request interface for socket_rest_supervisor(see below),
	/// logically it's a child class of socket_rest_supervisor.
	/// Derived class implements requests and responses via corresponding methods.
	/// You probably want to use socket_rest_supervisor_request.
	class socket_rest_supervisor_request_base : public socket_rest_supervisor_item
	{
		friend socket_rest_supervisor;

	protected:
		using socket_rest_supervisor_item::m_flags;
		static constexpr unsigned Repeat = Paused << 1;

		/// By default request is executed only once, then it's automatically removed from supervisor.
		/// With those methods you can suppress removal(for example you need to repeat request due to authorization).
		/// NOTE: reset_repeast is called automatically called after each request/response pair.
		bool should_repeat() const noexcept { return (m_flags.load(std::memory_order_relaxed) & Repeat) != 0; }
		void set_repeat() noexcept          { m_flags.fetch_or(Repeat, std::memory_order_relaxed); }
		void reset_repeat() noexcept        { m_flags.fetch_and(~Repeat, std::memory_order_relaxed); }

	protected:
		/// optional shared_state support
		virtual ext::shared_state_basic * get_shared_state() noexcept { return nullptr; }

	public:
		/// writes request into sock
		virtual void request(ext::socket_stream & stream) = 0;
		/// reads and processes response from socket
		virtual void response(ext::socket_stream & stream) = 0;
		/// one time execution does not needs scheduling
		virtual auto next_invoke() -> std::chrono::steady_clock::time_point override final;

	public:
		/// for socket_rest_supervisor use, calls request method
		virtual bool make_request(parent_lock & srs_lk, ext::socket_stream & stream) override;
		/// for socket_rest_supervisor use, calls process method
		virtual void process_response(parent_lock & srs_lk, ext::socket_stream & stream) override;
	};

	/// Abstract request with ext::future support socket_rest_supervisor(see below),
	/// logically it's a child class of socket_rest_supervisor.
	/// Derived class implements requests and responses via corresponding methods.
	template <class ReturnType, class RequestBase = socket_rest_supervisor_request_base>
	class socket_rest_supervisor_request :
		public RequestBase,
		public ext::shared_state<ReturnType>
	{
	private:
		typedef RequestBase                   request_base_type;
		typedef ext::shared_state<ReturnType> shared_state_type;

	public:
		typedef ReturnType               return_type;
		typedef ext::future<return_type> future_type;

	protected:
		ext::shared_state_basic * get_shared_state() noexcept override { return this; }

	public:
		unsigned addref() noexcept override           { return shared_state_type::addref(); }
		unsigned release() noexcept override          { return shared_state_type::release(); }
		unsigned use_count() const noexcept override  { return shared_state_type::use_count(); }

		void abandon() noexcept override { return shared_state_type::release_promise(); }

	public:
		// request and response should be implemented by derived class
		using request_base_type::request;
		using request_base_type::response;
	};

	/// Abstract subscription interface for socket_rest_supervisor(see below),
	/// logically it's a child class of socket_rest_supervisor.
	///
	/// Derived class implements requests and responses via corresponding methods.
	/// Implementation of those should provide strong exception guarantee
	/// after std::runtime_error exceptions and be able to continue work,
	/// or subscription can close itself in case of exception.
	/// 
	/// To self close - call close/do_close_request
	class socket_rest_supervisor_subscription :
		public socket_rest_supervisor_item,
		public abstract_subscription_controller
	{
	public:
		typedef abstract_subscription_controller    base_type;
		typedef socket_rest_supervisor_subscription self_type;
		friend socket_rest_supervisor;

	protected:
		using base_type::unique_lock;
		using base_type::mutex_type;
		using base_type::m_mutex;
		using base_type::m_state;

	protected:
		using socket_rest_supervisor_item::m_flags;
		static constexpr unsigned Pending = Paused << 1;

		/// Indicates that subscription has done request and waiting/processing response.
		/// It is for do_close_request - pending removal subscription is delayed until response processing is finished.
		bool is_pending() const noexcept { return (m_flags.load(std::memory_order_relaxed) & Pending) != 0; }
		void set_pending() noexcept { m_flags.fetch_or(Pending, std::memory_order_relaxed); }
		void reset_pending() noexcept { m_flags.fetch_and(~Pending, std::memory_order_relaxed); }

	public:
		unsigned addref()  noexcept override { return base_type::counter_addref(); }
		unsigned release() noexcept override { return base_type::counter_release(); }
		unsigned use_count() const noexcept override { return base_type::counter_usecount(); }

	protected:
		void do_close_request(unique_lock lk) override;
		void do_pause_request(unique_lock lk) override;
		void do_resume_request(unique_lock lk) override;

	public:
		/// writes request into sock
		virtual void request(ext::socket_stream & stream) = 0;
		/// reads and processes response from socket
		virtual void response(ext::socket_stream & stream) = 0;

		/// Returns time for next scheduled invocation.
		/// Normally called after request call, not necessary after response.
		/// 
		/// Typical implementation can schedule next invocation immediately, 
		/// or, in case no new data - return some delay.
		/// 
		/// It's okay to return time_point::max after request, and correct time_point after response.
		/// In case you you next_invoke is changed some where after response - 
		/// call notify() this will wake up internal thread.
		virtual auto next_invoke() -> std::chrono::steady_clock::time_point = 0;

	public:
		/// for socket_rest_supervisor use, calls request method
		virtual bool make_request(parent_lock & srs_lk, ext::socket_stream & stream) override;
		/// for socket_rest_supervisor use, calls process method
		virtual void process_response(parent_lock & srs_lk, ext::socket_stream & stream) override;
	};


	/// Manages and controls set of independent of each other subscription/requests for a socket connection.
	/// Typical example would be HTTP rest repeating requests.
	/// * Operations on socket should be stateless, in sense: 
	///   send request, receive response. Their should be not connection state, like envelope in SMTP.
	///   Of course subscription can abuse connection and send/receive data in single request call - this is not advised.
	///
	/// * class controls connection state, emits signals in case of connect/disconnect/connection lost.
	///   Between connect/disconnect subscription hold their current state, so they can continue work after restoring connection.
	///   
	/// * Subscription must provide strong exception garanties(only for std::runtime_error derived exceptions),
	///   so in case of error they can restore and continue working, or self close.
	///   
	/// Normally you would inherit/composite this class and add more concrete methods like:
	/// * ext::future<some_result> execute_some_request(...)
	/// * subscription_handle      load_some_data(some_callback, ...)
	/// 
	class socket_rest_supervisor : public abstract_connection_controller
	{
	private:
		typedef abstract_connection_controller  base_type;
		typedef socket_rest_supervisor          self_type;

	public:
		typedef ext::socket_stream::error_code_type    error_code_type;
		typedef ext::socket_stream::system_error_type  system_error_type;

		typedef socket_rest_supervisor_item           item;
		friend item;
		
		typedef socket_rest_supervisor_request_base  request_base;
		typedef socket_rest_supervisor_subscription  subscription;

		template <class Type, class RequestBase = request_base>
		using request = socket_rest_supervisor_request<Type, RequestBase>;

	protected:
		typedef boost::intrusive::base_hook<item::hook_type> item_list_option;

		typedef boost::intrusive::list<
			item, item_list_option,
			boost::intrusive::constant_time_size<false>
		> item_list;
		
		enum thread_state : bool
		{
			stopped, running,
		};

	protected:
		using base_type::mutex_type;
		using base_type::unique_lock;
		using base_type::m_mutex;

	protected:
		// This class should manage socket connection to some host:service 
		// and periodically execute some abstract subscriptions.
		// In fact subscriptions are sending request/parsing responses themselves,
		// and this class it more of manager of subscriptions, in addition to managing socket.
		// 
		// In basic scenario subscription sends some request to server, server processing it and sends back response.
		// While server preparing response - we are doing nothing(receiving nothing),
		// while we processing reply(parsing data, xml, json, etc) - server does nothing with us(of course it can serve other clients).
		// 
		// This introduce latency, to reduce it, because of subscriptions rest nature, 
		// one can send N(some small reasonable value, for example 4) requests 
		// and then one by one process replies, sending more requests in process.
		// This way, while we parsing first reply, server can process next request.
		// Though, this will not help if there is only one subscription.
		// 
		// Internally this class operates with list of subscriptions,
		// which lifetime managed via subscription intrusive counter.
		// Each subscription can be in following states(in addition to subscription_controller closed, paused, ...):
		// * waiting  - subscription does want to work in some near future, but not now;
		// * request  - subscription is ready to make request;
		// * reply    - subscription sent request and is to process reply;
		// 
		// When time comes - subscription are moved to pending list.
		// One from that list send request and moved to request list.
		// Those are processing requests and moved back to waiting queue.
		item_list m_items;
		ext::socket_stream m_sockstream;

		thread_state m_thread_state = stopped;
		bool m_connect_request = false;
		bool m_disconnect_request = false;

		// number of requests made before first response if processed,
		// by default 1, which makes it behave traditionally: send request - wait response.
		std::atomic_uint m_request_slots = ATOMIC_VAR_INIT(1);

		// thread running subscriptions
		std::thread m_thread;
		std::condition_variable m_request_event;
		
		// connection info
		std::string m_host;
		std::string m_service;
		std::chrono::steady_clock::duration m_timeout;
		ext::library_logger::logger * m_logger = nullptr;

		error_code_type m_lasterr;
		std::string m_lasterr_message;

	protected:
		using base_type::notify_connected;
		using base_type::notify_disconnected;

		void do_connect_request(unique_lock lk) override;
		void do_disconnect_request(unique_lock lk) override;

		/// returns std::chrono::steady_clock::time_point::max()
		static constexpr auto max_timepoint() -> std::chrono::steady_clock::time_point;

		/// waits for a connect/disconnect request, returns when got connect or stop request.
		/// returns thread state: stopped or running, this class stops thread on destruction.
		virtual thread_state wait_request(std::string & host, std::string & service, std::chrono::steady_clock::duration & timeout);
		/// executes connect, returns success of operation.
		virtual bool exec_connect(const std::string & host, const std::string & service, std::chrono::steady_clock::duration timeout);
		/// executes disconnect - closes socket, does some internal maintenance.
		virtual void exec_disconnect();

		/// connection error handler, calls notify_disconnected
		virtual void on_conn_error(std::runtime_error & ex);
		/// connection error handler, calls notify_disconnected
		virtual void on_socket_error();

	protected:
		/************************************************************************/
		/*                 Scheduling / Action management                       */
		/************************************************************************/
		/// schedules subscriptions from waiting into requests.
		/// Each subscription that is not paused and which next_invoke has passed - 
		/// is moved from waiting into requests.
		/// 
		/// returns time_point of nearest subscription if there no ready subscriptions; now otherwise.
		/// lk is a lock m_mutex used to protect waiting list.
		virtual auto schedule_subscriptions(unique_lock & lk, item_list & waiting, item_list & requests)
			-> std::chrono::steady_clock::time_point;
		
		/// This method with schedule_subscriptions are main methods of this class.
		/// 
		/// Runs subscriptions, obtained with schedule_subscriptions in a loop.
		/// Processed subscriptions are moved back into m_items and then passed to schedule_subscriptions again.
		/// returns only when some disconnect, connection error or, some exception occurred.
		virtual void run_subscriptions();

		/// main loading thread function.
		/// this one runs wait_request, exec_connect, run_subscriptions, exec_disconnect in a loop,
		/// until thread is stopped.
		virtual void thread_proc();

	public:
		/// setts connection address, they will be used on a next connect.
		void set_address(std::string host, std::string service);
		/// sets socket timeout, it will be used on a next connect.
		void set_timeout(std::chrono::steady_clock::duration timeout);
		/// Sets number of requests made before first response if processed.
		/// By default 1, which makes it behave traditionally: send request - wait response.
		/// nslots = 0 -> same as 1.
		/// This setting will be used only on next connect.
		void set_request_slots(unsigned nslots);
		/// sets optional logger, should be called prior first call to connect.
		/// (internal thread starts on first connect request)
		void set_logger(ext::library_logger::logger * logger);

		/// last error description
		std::string last_errormsg();
		/// last error code
		error_code_type last_error();

		/// Adds subscription. subscription will work continuously(depends on internal subscriptions parameters),
		/// returns handle, allowing controlling of subscription.
		/// To delete/stop subscription close it via handle.
		virtual void add_item(item * ptr);

		template <class Request>
		typename Request::future_type add_request(ext::intrusive_ptr<Request> ptr);
		subscription_handle add_subscription(ext::intrusive_ptr<subscription> ptr);

	public:
		socket_rest_supervisor() = default;
		~socket_rest_supervisor() noexcept;

		// nor movable, copyable
		socket_rest_supervisor(socket_rest_supervisor &&) = delete;
		socket_rest_supervisor & operator =(socket_rest_supervisor &&) = delete;
	};

	constexpr auto socket_rest_supervisor::max_timepoint() -> std::chrono::steady_clock::time_point
	{
		// MSVC 2015 and some version of gcc have a bug, 
		// that waiting in std::chrono::steady_clock::time_point::max() 
		// does not work due to integer overflow internally.
		// 
		// Prevent this by returning twice time_point::max() / 2, value still will be quite a big

		return std::chrono::steady_clock::time_point {
			std::chrono::steady_clock::duration {std::chrono::steady_clock::duration::max().count() / 2}
		};
	}

	constexpr auto socket_rest_supervisor_item::max_timepoint()
	{
		return socket_rest_supervisor::max_timepoint();
	}

	inline void socket_rest_supervisor_item::check_stream(ext::socket_stream & stream)
	{
		if (not stream)
			throw ext::socket_stream::system_error_type(stream.last_error());
	}

	inline std::string & socket_rest_supervisor_item::host() const noexcept
	{
		assert(m_owner);
		return m_owner->m_host;
	}

	inline std::mutex & socket_rest_supervisor_item::parent_mutex() const noexcept
	{
		assert(m_owner);
		return m_owner->m_mutex;
	}

	inline void socket_rest_supervisor_item::notify() const noexcept
	{
		assert(m_owner);
		m_owner->m_request_event.notify_all();
	}

	inline auto socket_rest_supervisor_item::logger() const noexcept
		-> ext::library_logger::logger *
	{
		return m_owner ? m_owner->m_logger : nullptr;
	}

	template <class Request>
	inline auto socket_rest_supervisor::add_request(ext::intrusive_ptr<Request> ptr) -> typename Request::future_type
	{
		add_item(ptr.get());
		return {ptr};
	}

	inline subscription_handle socket_rest_supervisor::add_subscription(ext::intrusive_ptr<subscription> ptr)
	{
		add_item(ptr.get());
		return {ptr};
	}

}} // namespace ext::netlib
