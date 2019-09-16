#pragma once
#include <mutex>

#include <boost/config.hpp>
#include <boost/signals2.hpp>

#include <ext/library_logger/logger.hpp>
#include <ext/net/subscription_controller.hpp>

namespace ext {
namespace net
{
	/// Abstract subscription_controller implementation: state_machine, futures.
	/// Actual pause/resume/close is delegated to derived class.
	/// On creation has opened state.
	/// 
	/// state protocol:
	///   * controller initializes connect request with do_connect_request,
	///     when connection is done - derived class notifies abstract_connection_controller via notify_connected.
	///   * controller initializes disconnect request do_disconnect_request,
	///     when disconnection is done - derived class notifies abstract_connection_controller via notify_disconnected notify_disconnected.
	///   * if connection is lost at any moment - derived class notifies abstract_connection_controller via notify_disconnected notify_disconnected.
	///   Cause of disconnection is stored in derived class(it's nature is implementation-specific).
	///   
	/// NOTE: subscription_controller is an interface in fact.
	///       To support parallel hierarchies of interfaces and implementation - virtual inheritance must be used.
	class abstract_subscription_controller : public virtual subscription_controller
	{
	protected:
		typedef std::mutex mutex_type;
		typedef std::unique_lock<mutex_type> unique_lock;
		typedef boost::signals2::signal<event_slot::signature_type> signal_type;

	protected:
		mutable mutex_type m_mutex;
		state_type m_state = opened;
		delayed_state_type m_delayed_state = normal;
		signal_type m_event_signal;

		ext::intrusive_ptr<ext::shared_state<void>> m_close_future;
		ext::intrusive_ptr<ext::shared_state<bool>> m_pause_future, m_resume_future;

	protected:
		/// optional logger support, this method always will be called under m_mutex lock
		virtual ext::library_logger::logger * get_logger() const { return nullptr; }

	public:
		/// name of this object, used mainly for logging purposes
		virtual std::string_view name() const { return "<anonymous>"; }

	protected:
		/// BadTransactionRequest handler (see connection_controller description), throws std::logic_error
		/*virtual*/ void BOOST_NORETURN on_bad_transaction();
		/// unexpected handler currently does nothing
		/*virtual*/ void on_unexpected(state_type ev);

		/// Emits signal sig with state, default implementation just calls sig(state).
		/// Can be overridden to customize signal emission, for example, serialize and signal calls via GUI thread queue
		virtual void emit_signal(signal_type & sig, state_type state);

		/// close request implementation, state-machine lock is passed.
		/// call is done after state is changed.
		/// implementation can manipulate lock is it pleases,
		/// caller has no more need in lock - passed by value.
		virtual void do_close_request(unique_lock lk) = 0;
		/// pause request implementation, state-machine lock is passed.
		/// call is done after state is changed.
		/// implementation can manipulate lock is it pleases,
		/// caller has no more need in lock - passed by value.
		virtual void do_pause_request(unique_lock lk) = 0;
		/// resume request implementation, state-machine lock is passed.
		/// call is done after state is changed.
		/// implementation can manipulate lock is it pleases,
		/// caller has no more need in lock - passed by value.
		virtual void do_resume_request(unique_lock lk) = 0;

		/// Derived class notifies about successful close request. thread safe.
		/// On call takes lock (lk.owns_lock() == true)
		/// lock is unlocked in process before emitting signals.
		/// You should avoid calling this method with eptr != nullptr.
		virtual void notify_closed(unique_lock lk, std::exception_ptr eptr = nullptr);
		/// Derived class notifies about execution of pause request. thread safe.
		/// * if success == true request future is set with true
		/// * if success == false and eptr != null, request future is set with set_exception(eptr)
		/// * otherwise request future is set with false
		/// 
		/// On call takes lock (lk.owns_lock() == true)
		/// lock is unlocked in process before emitting signals.
		virtual void notify_paused(unique_lock lk, bool success = true, std::exception_ptr eptr = nullptr);
		/// Derived class notifies about execution of resume request. thread safe.
		/// * if success == true request future is set with true
		/// * if success == false and eptr != null, request future is set with set_exception(eptr)
		/// * otherwise request future is set with false
		/// 
		/// On call takes lock (lk.owns_lock() == true)
		/// lock is unlocked in process before emitting signals.
		virtual void notify_resumed(unique_lock lk, bool success = true, std::exception_ptr eptr = nullptr);

		/// close state-machine event implementation.
		/// assert(lk.owns_lock() == true)
		ext::shared_future<void> do_close(unique_lock lk);
		/// pause state-machine event implementation.
		/// assert(lk.owns_lock() == true)
		ext::shared_future<bool> do_pause(unique_lock lk);
		/// resume state-machine event implementation.
		/// assert(lk.owns_lock() == true)
		ext::shared_future<bool> do_resume(unique_lock lk);

		/// returns current state-machine state
		/// assert(lk.owns_lock() == true)
		state_type get_state(unique_lock & lk) { return  m_state; }

	public:
		/// current state of connection,
		/// actually it can be changed immediately after call.
		state_type get_state() override;
		/// Makes close request.
		/// Returns future<void> - result of connection
		ext::shared_future<void> close() override;
		/// Makes pause request.
		/// Returns future<bool> - result of connection
		/// @Throws std::logic_error, see class decription
		ext::shared_future<bool> pause() override;
		/// Makes resume request.
		/// Returns future<bool> - result of connection
		/// @Throws std::logic_error, see class decription
		ext::shared_future<bool> resume() override;
		/// event signal, event is identified with state_type
		boost::signals2::connection on_event(const event_slot & slot) override
		{ return m_event_signal.connect(slot); }

	public:
		abstract_subscription_controller();
		~abstract_subscription_controller() noexcept;
	};
}}
