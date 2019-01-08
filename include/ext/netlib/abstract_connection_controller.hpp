#pragma once
#include <mutex>

#include <boost/config.hpp>
#include <boost/signals2.hpp>
#include <ext/netlib/connection_controller.hpp>

namespace ext {
namespace netlib
{
	/// Abstract connection_controller implementation: state_machine, futures.
	/// Actual connection/disconnection is delegated to derived class.
	///
	/// state protocol:
	///   * controller initializes connect request with do_connect_request,
	///     when connection is done - derived class notifies abstract_connection_controller via notify_connected.
	///   * controller initializes disconnect request do_disconnect_request,
	///     when disconnection is done - derived class notifies abstract_connection_controller via notify_disconnected notify_disconnected.
	///   * if connection is lost at any moment - derived class notifies abstract_connection_controller via notify_disconnected notify_disconnected.
	///   Cause of disconnection is stored in derived class(it's nature is implementation-specific).
	///   
	/// NOTE: connection_controller is an interface in fact.
	///       To support parallel hierarchies of interfaces and implementation - virtual inheritance must be used.
	class abstract_connection_controller : public virtual connection_controller
	{
	protected:
		typedef std::mutex                    mutex_type;
		typedef std::unique_lock<mutex_type>  unique_lock;

		typedef boost::signals2::signal<event_slot::signature_type> event_sig;

	protected:
		mutable mutex_type m_mutex;    /// mutex guarding state-machine, can also be used by derived class
		state_type m_state = offline;  /// state-machine state
		event_sig m_event_signal;

		ext::intrusive_ptr<ext::shared_state<bool>> m_connect_future;
		ext::intrusive_ptr<ext::shared_state<void>> m_disconnect_future;
		
	protected:
		/// BadTransactionRequest handler (see connection_controller description), throws std::logic_error
		/*virtual*/ void BOOST_NORETURN on_bad_transaction();
		/// BadConnectRequest handler (see connection_controller description), throws std::logic_error
		/*virtual*/ void BOOST_NORETURN on_bad_connect_request();

		/// Emits signal sig with state, default implementation just calls sig(state).
		/// Can be overridden to customize signal emission, for example, serialize and signal calls via GUI thread queue
		virtual void emit_signal(event_sig & sig, event_type ev);

		/// connect request implementation, state-machine lock is passed.
		/// call is done after state is changed.
		/// implementation can manipulate lock is it pleases,
		/// caller has no more need in lock - passed by value.
		virtual void do_connect_request(unique_lock lk) = 0;
		/// disconnect request implementation, state-machine lock is passed.
		/// call is done after state is changed.
		/// implementation can manipulate lock is it pleases,
		/// caller has no more need in lock - passed by value.
		virtual void do_disconnect_request(unique_lock lk) = 0;

		/// Derived class notifies about execution of connect request. thread safe.
		/// * if success == true request future is set with true
		/// * if success == false and eptr != null, request future is set with set_exception(eptr)
		/// * otherwise request future is set with false
		/// 
		/// On call takes lock (lk.owns_lock() == true)
		/// lock is unlocked in process before emitting signals.
		void notify_connected(unique_lock lk, bool success = true, std::exception_ptr eptr = nullptr);
		/// Derived class notifies about disconnect/connection loss. thread safe.
		/// On call takes lock (lk.owns_lock() == true)
		/// lock is unlocked in process before emitting signals.
		void notify_disconnected(unique_lock lk);

		/// connect state-machine event implementation.
		/// assert(lk.owns_lock() == true)
		ext::shared_future<bool> do_connect(unique_lock & lk);
		/// disconnect state-machine event implementation.
		/// assert(lk.owns_lock() == true)
		ext::shared_future<void> do_disconnect(unique_lock & lk);
		/// returns current state-machine state
		/// assert(lk.owns_lock() == true)
		state_type get_state(unique_lock & lk) { return  m_state; }

	public:
		/// current state
		state_type get_state() override;
		/// Make connect request.
		/// Returns future<bool> - result of connection 
		/// @Throws std::logic_error see class description
		ext::shared_future<bool> connect() override;
		/// Makes disconnect request.
		/// Returns future<void> - result of disconnection
		ext::shared_future<void> disconnect() override;

		boost::signals2::connection on_event(const event_slot & slot) override
		{ return m_event_signal.connect(slot); }

	public:
		abstract_connection_controller();
		~abstract_connection_controller() noexcept;
	};
}}
