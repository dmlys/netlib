#pragma once
#include <boost/config.hpp>
#include <boost/signals2.hpp>
#include <boost/thread/mutex.hpp>
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
	private:
		ext::intrusive_ptr<ext::shared_state<bool>> m_connect_future;
		ext::intrusive_ptr<ext::shared_state<void>> m_disconnect_future;

	protected:
		typedef boost::mutex                    mutex_type;
		typedef boost::unique_lock<mutex_type>  unique_lock;

		typedef boost::signals2::signal< connected_slot::signature_type        > connected_sig;
		typedef boost::signals2::signal< disconnected_slot::signature_type     > disconnected_sig;
		typedef boost::signals2::signal< connection_error_slot::signature_type > connection_error_sig;
		typedef boost::signals2::signal< connection_lost_slot::signature_type  > connection_lost_sig;

		/// mutex guarding state-machine, can also be used by derived class
		mutex_type m_mutex;

	private:
		/// state is private, derived class should not have any influence on state
		state_type m_state = offline;  /// state-machine state
	
	protected:
		/// signals
		connected_sig m_connected_signal;
		disconnected_sig m_disconnected_signal;
		connection_error_sig m_connection_error_signal;
		connection_lost_sig m_connection_lost_signal;
		
	protected:
		/// BadTransactionRequest handler (see connection_controller description), throws std::logic_error
		/*virtual*/ void BOOST_NORETURN on_bad_transaction();
		/// BadConnectRequest handler (see connection_controller description), throws std::logic_error
		/*virtual*/ void BOOST_NORETURN on_bad_connect_request();

		/// connect request implementation, state-machine lock is passed.
		/// call is done after state is changed.
		/// implementation can manipulate lock is it pleases,
		/// caller has no more need in lock, it will unlock it anyway after call(unless it's already unlocked)
		virtual void do_connect_request(unique_lock & lk) = 0;
		/// disconnect request implementation, state-machine lock is passed.
		/// call is done after state is changed.
		/// implementation can manipulate lock is it pleases,
		/// caller has no more need in lock, it will unlock it anyway after call(unless it's already unlocked)
		virtual void do_disconnect_request(unique_lock & lk) = 0;

		/// Derived class notifies about successful connection request. thread safe.
		/// On call takes lock (lk.owns_lock() == true)
		/// lock is unlocked in process before emitting signals.
		void notify_connected(unique_lock lk);
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
		state_type get_state() override final;
		/// Make connect request.
		/// Returns future<bool> - result of connection 
		/// @Throws std::logic_error see class decription
		ext::shared_future<bool> connect() override final;
		/// Makes disconnect request.
		/// Returns future<void> - result of disconnection
		ext::shared_future<void> disconnect() override final;

		boost::signals2::connection on_connected(const connected_slot & slot) override
		{ return m_connected_signal.connect(slot); }
		boost::signals2::connection on_disconnected(const disconnected_slot & slot) override
		{ return m_disconnected_signal.connect(slot); }
		boost::signals2::connection on_connection_lost(const connection_lost_slot & slot) override
		{ return m_connection_lost_signal.connect(slot); }
		boost::signals2::connection on_connection_error(const connection_error_slot & slot) override
		{ return m_connection_error_signal.connect(slot); }

	public:
		abstract_connection_controller();
		~abstract_connection_controller();
	};
}}
