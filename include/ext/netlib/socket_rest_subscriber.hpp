#pragma once
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
	class socket_rest_subscriber;
	class socket_rest_subscriber_subscription;

	/// Abstract subscription interface for socket_rest_subscriber,
	/// derived class implement requests and responses via corresponding methods.
	/// 
	/// Implementation of request/response should provide strong exception guarantee
	/// after std::runtime_error exceptions and be able to continue work,
	/// or subscription can close itself in case of exception.
	/// 
	/// To self close - call close/do_close_request
	class socket_rest_subscriber_subscription :
		public abstract_subscription_controller,
		public boost::intrusive::list_base_hook<
			boost::intrusive::link_mode<boost::intrusive::link_mode_type::auto_unlink>
		>
	{
	public:
		typedef abstract_subscription_controller    base_type;
		typedef socket_rest_subscriber_subscription self_type;
		friend socket_rest_subscriber;

	protected:
		typedef boost::intrusive::list_base_hook<
			boost::intrusive::link_mode<boost::intrusive::link_mode_type::auto_unlink>
		> hook_type;

	protected:
		using base_type::unique_lock;
		using base_type::mutex_type;
		using base_type::m_mutex;
		using base_type::m_state;

		typedef unique_lock parent_lock;
		socket_rest_subscriber * m_owner = nullptr;
		
		/// can it be non atomic? 
		std::atomic_bool m_paused = false;
		std::atomic_bool m_pending = false;

	protected:
		void set_parent(socket_rest_subscriber * parent) noexcept { m_owner = parent; }
		bool is_orphan() const noexcept { return m_owner == nullptr; }
		bool is_paused() const noexcept { return m_paused.load(std::memory_order_relaxed); }

		std::string & host() const noexcept;
		void notify() const noexcept;
		auto logger() const noexcept -> ext::library_logger::logger *;

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
		/// for socket_rest_subscriber use, in process calls request method
		void make_request(parent_lock & srs_lk, ext::socket_stream & stream);
		/// for socket_rest_subscriber use, in process calls process method
		void process_response(parent_lock & srs_lk, ext::socket_stream & stream);
	};


	/// Manages and controls set of independent of each other subscription for a socket connection.
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
	class socket_rest_subscriber : public abstract_connection_controller
	{
	private:
		typedef abstract_connection_controller  base_type;
		typedef socket_rest_subscriber          self_type;

	public:
		typedef socket_rest_subscriber_subscription   subscription;
		typedef ext::intrusive_ptr<subscription>      subscription_ptr;
		typedef ext::socket_stream::error_code_type   error_code_type;
		friend subscription;

	protected:
		typedef boost::intrusive::base_hook<subscription::hook_type> subscription_list_option;

		typedef boost::intrusive::list<
			subscription,
			subscription_list_option,
			boost::intrusive::constant_time_size<false>
		> subscription_list;
		
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
		subscription_list m_subscriptions;
		ext::socket_stream m_sockstream;

		thread_state m_thread_state = stopped;
		bool m_connect_request = false;
		bool m_disconnect_request = false;

		// number of requests made before first response if processed,
		// by default 1, which makes it behave traditionally: send request - wait response.
		std::atomic_uint m_request_slots = 1;

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
		virtual auto schedule_subscriptions(unique_lock & lk, subscription_list & waiting, subscription_list & requests)
			-> std::chrono::steady_clock::time_point;
		
		/// This method with schedule_subscriptions are main methods of this class.
		/// 
		/// Runs subscriptions, obtained with schedule_subscriptions in a loop.
		/// Processed subscriptions are moved back into m_subscriptions and then passed to schedule_subscriptions again.
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
		void set_timeout(std::chrono::system_clock::duration timeout);
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
		virtual subscription_handle add_subscription(subscription_ptr sub);

	public:
		socket_rest_subscriber() = default;
		~socket_rest_subscriber() noexcept;

		// nor movable, copyable
		socket_rest_subscriber(socket_rest_subscriber &&) = delete;
		socket_rest_subscriber & operator =(socket_rest_subscriber &&) = delete;
	};

	inline std::string & socket_rest_subscriber_subscription::host() const noexcept
	{
		assert(m_owner);
		return m_owner->m_host;
	}

	inline void socket_rest_subscriber_subscription::notify() const noexcept
	{
		m_owner->m_request_event.notify_all();
	}

	inline auto socket_rest_subscriber_subscription::logger() const noexcept
		-> ext::library_logger::logger *
	{
		return m_owner ? m_owner->m_logger : nullptr;
	}
}}
